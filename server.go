package app

import (
	"context"
	"fmt"
	"github.com/MultiAdaptive/transitStation/config"
	"github.com/MultiAdaptive/transitStation/contract"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/gorilla/mux"
	kzgsdk "github.com/multiAdaptive/kzg-sdk"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	storageManagerAddress = "0x44214b40b88BeD3424b2684bE6b102fD3BCA4a09"
	cmManagerAddress      = "0xb945872cbF327DA5CBEb6aE7286ccEE6CAaBA3B2"
	nodeManagerAddress    = "0xed592c8F0B13bb8A761BFFb6140720D89552999B"
)

type Server struct {
	httpServer     *http.Server
	mu             sync.Mutex
	log            *logrus.Logger
	auth           *bind.TransactOpts
	SignerClient   *ethclient.Client
	SenderClient   *ethclient.Client
	config         *config.Config
	ctx            context.Context
	kzgCDK         *kzgsdk.MultiAdaptiveSdk
	storageManager *contract.StorageManager
	cmManager      *contract.CommitmentManager
	nodeManager    *contract.NodeManager
	wg        sync.WaitGroup
}

type RPCDA struct {
	Sender     common.Address `json:"sender"`
	Length     hexutil.Uint64 `json:"length"`
	Index      hexutil.Uint64 `json:"index"`
	Commitment hexutil.Bytes  `json:"commitment"`
	Data       hexutil.Bytes  `json:"data"`
	SignHash   []common.Hash  `json:"sign"`
	TxHash     common.Hash    `json:"txhash"`
	ExtraData  hexutil.Bytes  `json:"extraData"`
}

func NewServer(ctx context.Context, cfg *config.Config, logger *logrus.Logger) (*Server, error) {
	exePath, _ := os.Executable()
	exeDir := filepath.Dir(exePath)
	if strings.HasSuffix(exeDir, "/build") {
		exeDir = strings.TrimSuffix(exeDir, "/build")
	}
	sdk, err := kzgsdk.InitMultiAdaptiveSdk(exeDir + "/srs")
	if err != nil {
		log.Fatalf("kzgsdk Error: %s", err)
		return nil, err
	}
	client, auth, err := initEthClient(cfg.PrivateKey, cfg.URL, cfg.ChainID)
	if err != nil {
		log.Errorf("Failed to initialize Ethereum client: %v", err)
		return nil, err
	}
	storageManager, err := contract.NewStorageManager(common.HexToAddress(storageManagerAddress), client)
	if err != nil {
		logger.Fatalf("NewStorageManager----failed error:%s", err)
		return nil, err
	}

	cmManager, err := contract.NewCommitmentManager(common.HexToAddress(cmManagerAddress), client)
	if err != nil {
		logger.Fatalf("NewCommitmentManager----failed error:%s", err)
		return nil, err
	}

	nodeManager, err := contract.NewNodeManager(common.HexToAddress(nodeManagerAddress), client)
	if err != nil {
		logger.Fatalf("NewNodeManager----failed error:%s", err)
		return nil, err
	}

	r := mux.NewRouter()
	srv := &Server{
		httpServer: &http.Server{
			Addr:    cfg.ServerAddress,
			Handler: r,
		},
		log:            logger,
		SenderClient:   client,
		storageManager: storageManager,
		cmManager:      cmManager,
		nodeManager:    nodeManager,
		kzgCDK:         sdk,
		auth:           auth,
		config:         cfg,
		ctx:            ctx,
	}

	r.HandleFunc("/put/", srv.putWithoutCommitmentHandler).Methods("POST")
	r.HandleFunc("/put/{commitment}", srv.putWithCommitmentHandler).Methods("POST")
	r.HandleFunc("/get/{commitment}", srv.getCommitmentHandler).Methods("GET")

	logger.Printf("transitStation config: nodeGroup:%s chainID:%d ", cfg.NodeGroup, cfg.ChainID)
	return srv, nil
}

func (s *Server) Start() error {
	s.log.Infof("Starting server on %s", s.httpServer.Addr)
	s.wg.Add(1)
	go s.loop()
	return s.httpServer.ListenAndServe()
}

func (s *Server) loop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.log.Info("transit Station is running.......")
		case <-s.ctx.Done():
			s.log.Info("Stopping loop due to context cancellation.")
			return
		}
	}
}

func (s *Server) Shutdown(ctx context.Context) error {
	defer s.wg.Done()
	s.log.Info("Shutting down server...")
	return s.httpServer.Shutdown(ctx)
}

// Handler for PUT /put
// The data is in the request body as []byte
func (s *Server) putWithoutCommitmentHandler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") != "application/octet-stream" {
		http.Error(w, "Unsupported Content-Type", http.StatusUnsupportedMediaType)
		return
	}
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()
	s.log.Println("putWithoutCommitmentHandler is calling-----")
	if len(data) == 0 {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	cm, proof, err := s.kzgCDK.GenerateDataCommitAndProof(data)
	if err != nil {
		s.log.Fatalf("kzgsdk GenerateDataCommitAndProof Error: %s", err)
		http.Error(w, "kzgsdk GenerateDataCommitAndProof Error", http.StatusBadRequest)
		return
	}

	nodeGroupKey := common.HexToHash(s.config.NodeGroup)
	nameSpaceKey := common.HexToHash(s.config.Namespace)
	nodeGroup, err := s.storageManager.NODEGROUP(nil, nodeGroupKey)
	if err != nil {
		s.log.Fatalf("NODEGROUP----failed error:%s", err)
		http.Error(w, "NODEGROUP failed", http.StatusBadRequest)
		return
	}

	signatures := make([][]byte, 0)
	errList := make([]error, 0)
	timeNow := time.Now()
	timeOut := timeNow.Add(24 * time.Hour).Unix()
	sender := s.auth.From
	index, err := s.cmManager.Indices(nil, sender)
	length := len(data)
	result := make([]byte, 0)
	result = append(result, 1)
	result = append(result, cm.Marshal()...)
	s.log.Printf("cm string:%s", common.Bytes2Hex(result))
	s.log.Println("transit Station is prepare getting signature")
	for _, add := range nodeGroup.Addrs {
		info, err := s.nodeManager.BroadcastingNodes(nil, add)
		if err != nil {
			continue
		}
		s.SignerClient, err = ethclient.Dial(info.Url)
		if err != nil {
			s.log.Fatalf("Getting connection with url:%s err:%s", info.Url, err)
			http.Error(w, "Getting connection Error", http.StatusBadRequest)
		}
		claimedValue := proof.ClaimedValue.Marshal()
		s.log.Printf("transit Station is getting signature with url:%s", info.Url)
		result, err := s.getSignature(sender, index.Uint64(), uint64(length), cm.Marshal(), data, nodeGroupKey, proof.H.Marshal(), claimedValue, uint64(timeOut), result)
		if err != nil {
			s.log.Printf("sendDAByParams--err:%s", err.Error())
			errList = append(errList, err)
			continue
		}
		signatures = append(signatures, result)
	}

	if len(signatures) == 0 && len(errList) > 0 {
		s.log.Printf("send to signature failed  error:%s", errList[0])
		http.Error(w, "send to signature failed", http.StatusBadRequest)
		return
	}

	commitData := contract.PairingG1Point{
		X: new(big.Int).SetBytes(cm.X.Marshal()),
		Y: new(big.Int).SetBytes(cm.Y.Marshal()),
	}
	s.log.Println("transit Station is prepare send signature to contract")
	tx, err := s.cmManager.SubmitCommitment(s.auth, new(big.Int).SetInt64(int64(length)), new(big.Int).SetInt64(timeOut), nameSpaceKey, nodeGroupKey, signatures, commitData)
	if err != nil {
		s.log.Printf("SubmitCommitment failed:%s", err.Error())
		http.Error(w, "SubmitCommitment failed", http.StatusBadRequest)
		return
	}
	// 等待交易被打包并获取交易哈希
	s.log.Printf("SubmitCommitment tx Hash:%s", tx.Hash().Hex())
	// 等待交易被确认
	receipt, err := bind.WaitMined(s.ctx, s.SenderClient, tx)
	if err != nil {
		errStr := fmt.Sprintf("cant WaitMined by contract address err:%s", err.Error())
		s.log.Fatal(errStr)
		http.Error(w, errStr, http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	if receipt.Status == types.ReceiptStatusFailed {
		s.log.Fatal("transaction failed tx Hash:%s", tx.Hash().Hex())
		w.WriteHeader(http.StatusInternalServerError)
	} else {
		s.log.Printf("transaction successful tx Hash:%s", tx.Hash().Hex())
		s.log.Printf("cm string:%s", common.Bytes2Hex(cm.Marshal()))
		w.WriteHeader(http.StatusOK)
		w.Write(result)
	}
}

// Handler for PUT /put/<hex_encoded_commitment>
// The commitment is passed in the URL, and the data is in the request body as []byte
func (s *Server) putWithCommitmentHandler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") != "application/octet-stream" {
		http.Error(w, "Unsupported Content-Type", http.StatusUnsupportedMediaType)
		return
	}
	s.log.Println("putWithCommitmentHandler is calling-----")
	// Extract the hex-encoded commitment from the URL
	vars := mux.Vars(r)
	commitment := vars["commitment"]
	s.log.Println("r.URL.String()-----", r.URL.String())
	if len(commitment) == 0 {
		s.log.Println("Get commitment params is missing")
		http.Error(w, "commitment params is missing", http.StatusUnsupportedMediaType)
		return
	}
	commitmentByte := common.Hex2Bytes(commitment[2:])// 跳过前缀"0x"
	preimage, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return
	}
	s.log.Printf("transitStation is handling post commitment")
	cm, proof, err := s.kzgCDK.GenerateDataCommitAndProof(preimage)
	if err != nil {
		s.log.Fatalf("kzgsdk GenerateDataCommitAndProof Error: %s", err)
		http.Error(w, "kzgsdk GenerateDataCommitAndProof Error", http.StatusBadRequest)
		return
	}

	nodeGroupKey := common.HexToHash(s.config.NodeGroup)
	nameSpaceKey := common.HexToHash(s.config.Namespace)
	nodeGroup, err := s.storageManager.NODEGROUP(nil, nodeGroupKey)
	if err != nil {
		s.log.Fatalf("NODEGROUP----failed error:%s", err)
		http.Error(w, "Get NODEGROUP Error", http.StatusBadRequest)
		return
	}

	signatures := make([][]byte, 0)
	errList := make([]error, 0)
	timeNow := time.Now()
	timeOut := timeNow.Add(24 * time.Hour).Unix()
	sender := s.auth.From
	index, err := s.cmManager.Indices(nil, sender)
	length := len(preimage)
	s.log.Printf("transitStation is prepare getting signature commitment:%s", commitment)
	for _, add := range nodeGroup.Addrs {
		info, err := s.nodeManager.BroadcastingNodes(nil, add)
		if err != nil {
			continue
		}
		s.SignerClient, err = ethclient.Dial(info.Url)
		if err != nil {
			s.log.Fatalf("Getting connection with url:%s err:%s", info.Url, err)
			http.Error(w, "Getting connection Error", http.StatusBadRequest)
		}
		s.log.Printf("transit Station is getting signature with url:%s", info.Url)
		claimedValue := proof.ClaimedValue.Marshal()
		result, err := s.getSignature(sender, index.Uint64(), uint64(length), cm.Marshal(), preimage, nodeGroupKey, proof.H.Marshal(), claimedValue, uint64(timeOut), commitmentByte)
		if err != nil {
			log.Println(err.Error())
			errList = append(errList, err)
			continue
		}
		signatures = append(signatures, result)
	}

	if len(signatures) == 0 && len(errList) > 0 {
		s.log.Printf("send to signature failed  error:%s", errList[0])
		http.Error(w, "Get NODEGROUP Error", http.StatusBadRequest)
		return
	}

	commitData := contract.PairingG1Point{
		X: new(big.Int).SetBytes(cm.X.Marshal()),
		Y: new(big.Int).SetBytes(cm.Y.Marshal()),
	}
	s.log.Printf("transitStation is prepare getting signature commitment:%s", commitment)
	tx, err := s.cmManager.SubmitCommitment(s.auth, new(big.Int).SetInt64(int64(length)), new(big.Int).SetInt64(timeOut), nameSpaceKey, nodeGroupKey, signatures, commitData)
	if err != nil {
		s.log.Printf("SubmitCommitment failed:%s", err.Error())
		http.Error(w, "SubmitCommitment failed", http.StatusBadRequest)
		return
	}
	// 等待交易被打包并获取交易哈希
	log.Printf("SubmitCommitment tx Hash:%s", tx.Hash().Hex())
	// 等待交易被确认
	receipt, err := bind.WaitMined(s.ctx, s.SenderClient, tx)
	if err != nil {
		errStr := fmt.Sprintf("cant WaitMined by contract address err:%s", err.Error())
		s.log.Fatal(errStr)
		http.Error(w, errStr, http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	if receipt.Status == types.ReceiptStatusFailed {
		s.log.Fatalf("transaction failed tx Hash:%s", tx.Hash().Hex())
		w.WriteHeader(http.StatusInternalServerError)
	} else {
		s.log.Printf("transaction successful tx Hash:%s", tx.Hash().Hex())
		w.WriteHeader(http.StatusOK)
	}
}

func (s *Server) getSignature(sender common.Address, index, length uint64, commitment, data []byte, nodeGroupKey [32]byte, proof, claimedValue []byte, timeout uint64, extraData []byte) ([]byte, error) {
	var result []byte
	// Call the eth_sendDAByParams method to get the signature
	err := s.SignerClient.Client().CallContext(s.ctx, &result, "mta_sendDAByParams", sender, index, length, commitment, data, nodeGroupKey, proof, claimedValue, timeout, extraData)
	return result, err
}

func (s *Server) getCommitmentHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	commitment := vars["commitment"]
	s.log.Printf("get commit is %s",commitment)
	// 将hex编码的字符串解码为字节数组
	commitmentData := common.Hex2Bytes(commitment[2:]) // 跳过前缀"0x"
	if len(commitmentData) == 0 {
		http.Error(w, "Invalid hex encoded commitment", http.StatusBadRequest)
		return
	}
	s.log.Println("getCommitmentHandler--is calling-----")
	nodeGroupKey := common.HexToHash(s.config.NodeGroup)
	//nameSpaceKey := common.HexToHash(s.config.Namespace)
	nodeGroup, err := s.storageManager.NODEGROUP(nil, nodeGroupKey)
	if err != nil {
		s.log.Fatalf("NODEGROUP----failed error:%s", err)
		http.Error(w, "NODEGROUP failed", http.StatusBadRequest)
		return
	}
	var daDetail RPCDA
	var daGetErr error
	s.log.Println("transitStation is prepare get DA by commitment")
	for _, add := range nodeGroup.Addrs {
		info, err := s.nodeManager.BroadcastingNodes(nil, add)
		if err != nil {
			continue
		}
		s.log.Printf("transitStation is getting DA by commitment: %s", common.Bytes2Hex(commitmentData))
		s.SignerClient, err = ethclient.Dial(info.Url)
		if err != nil {
			s.log.Fatalf("Getting connection with url:%s err:%s", info.Url, err)
			http.Error(w, "Getting connection Error", http.StatusBadRequest)
		}
		daGetErr = s.SignerClient.Client().CallContext(s.ctx, &daDetail, "mta_getDAByExtraData", commitmentData)
		if daGetErr != nil || &daDetail == nil {
			daGetErr = s.SignerClient.Client().CallContext(s.ctx, &daDetail, "mta_getDAByCommitment", commitmentData)
			if daGetErr != nil || &daDetail == nil {
				s.log.Printf("get da by commitment err:%s url:%s", daGetErr.Error(), info.Url)
				continue
			}
		}
	}

	if daGetErr != nil || &daDetail == nil {
		s.log.Warnf("Data not found for commitment: %s", commitment)
		http.Error(w, "Data not found", http.StatusNotFound)
		return
	}

	s.log.Infof("Retrieved data for commitment: %s", commitment)

	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	w.Write(daDetail.Data)
}

func initEthClient(privateKey, url string, chainId uint64) (*ethclient.Client, *bind.TransactOpts, error) {
	submitClient, err := ethclient.Dial(url)
	if err != nil {
		return nil, nil, err
	}
	privateKeyECDSA, err := crypto.HexToECDSA(privateKey)
	if err != nil {
		return nil, nil, err
	}

	auth, err := bind.NewKeyedTransactorWithChainID(privateKeyECDSA, big.NewInt(int64(chainId)))
	return submitClient, auth, err
}
