package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/MultiAdaptive/transitStation/config"
	"github.com/MultiAdaptive/transitStation/contract"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/kzg"
	"github.com/ethereum/go-ethereum/accounts/abi"
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
	method              = "submitCommitment"
	gasLimit            = 500000 //The limitations set by gas are simply to prevent underestimated projections arising from the submission of the contract object.
	contractABI         = `[{"inputs":[],"stateMutability":"nonpayable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"uint8","name":"version","type":"uint8"}],"name":"Initialized","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"previousOwner","type":"address"},{"indexed":true,"internalType":"address","name":"newOwner","type":"address"}],"name":"OwnershipTransferred","type":"event"},{"anonymous":false,"inputs":[{"components":[{"internalType":"uint256","name":"X","type":"uint256"},{"internalType":"uint256","name":"Y","type":"uint256"}],"indexed":false,"internalType":"struct Pairing.G1Point","name":"commitment","type":"tuple"},{"indexed":false,"internalType":"uint256","name":"timestamp","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"nonce","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"index","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"len","type":"uint256"},{"indexed":false,"internalType":"bytes32","name":"nodeGroupKey","type":"bytes32"},{"indexed":false,"internalType":"bytes32","name":"nameSpaceKey","type":"bytes32"},{"indexed":false,"internalType":"bytes[]","name":"signatures","type":"bytes[]"}],"name":"SendDACommitment","type":"event"},{"inputs":[],"name":"baseFee","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"","type":"uint256"}],"name":"commitments","outputs":[{"internalType":"uint256","name":"X","type":"uint256"},{"internalType":"uint256","name":"Y","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"name":"daDetails","outputs":[{"internalType":"uint256","name":"timestamp","type":"uint256"},{"internalType":"bytes32","name":"hashSignatures","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"_nonce","type":"uint256"}],"name":"getDADetailsByNonce","outputs":[{"components":[{"internalType":"uint256","name":"timestamp","type":"uint256"},{"internalType":"bytes32","name":"hashSignatures","type":"bytes32"}],"internalType":"struct CommitmentManager.DADetails","name":"","type":"tuple"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"_user","type":"address"},{"internalType":"uint256","name":"_index","type":"uint256"}],"name":"getDADetailsByUserAndIndex","outputs":[{"components":[{"internalType":"uint256","name":"timestamp","type":"uint256"},{"internalType":"bytes32","name":"hashSignatures","type":"bytes32"}],"internalType":"struct CommitmentManager.DADetails","name":"","type":"tuple"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"_nameSpaceKey","type":"bytes32"},{"internalType":"uint256","name":"_index","type":"uint256"}],"name":"getNameSpaceCommitment","outputs":[{"components":[{"internalType":"uint256","name":"X","type":"uint256"},{"internalType":"uint256","name":"Y","type":"uint256"}],"internalType":"struct Pairing.G1Point","name":"","type":"tuple"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"_user","type":"address"},{"internalType":"uint256","name":"_index","type":"uint256"}],"name":"getUserCommitment","outputs":[{"components":[{"internalType":"uint256","name":"X","type":"uint256"},{"internalType":"uint256","name":"Y","type":"uint256"}],"internalType":"struct Pairing.G1Point","name":"","type":"tuple"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"indices","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"contract NodeManager","name":"_nodeManager","type":"address"},{"internalType":"contract StorageManager","name":"_storageManagement","type":"address"}],"name":"initialize","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"","type":"bytes32"},{"internalType":"uint256","name":"","type":"uint256"}],"name":"nameSpaceCommitments","outputs":[{"internalType":"uint256","name":"X","type":"uint256"},{"internalType":"uint256","name":"Y","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"name":"nameSpaceIndex","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"nodeManager","outputs":[{"internalType":"contract NodeManager","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"nonce","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"owner","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"renounceOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"_newFee","type":"uint256"}],"name":"setBaseFee","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"storageManagement","outputs":[{"internalType":"contract StorageManager","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"_length","type":"uint256"},{"internalType":"uint256","name":"_timeout","type":"uint256"},{"internalType":"bytes32","name":"_nameSpaceKey","type":"bytes32"},{"internalType":"bytes32","name":"_nodeGroupKey","type":"bytes32"},{"internalType":"bytes[]","name":"_signatures","type":"bytes[]"},{"components":[{"internalType":"uint256","name":"X","type":"uint256"},{"internalType":"uint256","name":"Y","type":"uint256"}],"internalType":"struct Pairing.G1Point","name":"_commitment","type":"tuple"}],"name":"submitCommitment","outputs":[],"stateMutability":"payable","type":"function"},{"inputs":[{"internalType":"address","name":"newOwner","type":"address"}],"name":"transferOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"","type":"address"},{"internalType":"uint256","name":"","type":"uint256"}],"name":"userCommitments","outputs":[{"internalType":"uint256","name":"X","type":"uint256"},{"internalType":"uint256","name":"Y","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"version","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"withdraw","outputs":[],"stateMutability":"nonpayable","type":"function"}]`
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
}
type RPCDA struct {
	Sender     common.Address `json:"sender"`
	Length     hexutil.Uint64 `json:"length"`
	Index      hexutil.Uint64 `json:"index"`
	Commitment hexutil.Bytes  `json:"commitment"`
	Data       hexutil.Bytes  `json:"data"`
	SignHash   []common.Hash  `json:"sign"`
	TxHash     common.Hash    `json:"txhash"`
	MetaData   hexutil.Bytes  `json:"metaData"`
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
	return s.httpServer.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
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
	if err == nil {
		err = s.getSignatureAndSubmitToChain(cm,proof,data,[]byte{})
		result := make([]byte,0)
		result = append(result, 1)
		result = append(result, cm.Marshal()...)
		w.Header().Set("Content-Type", "application/octet-stream")
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
		}else {
			s.log.Printf("cm string:%s", common.Bytes2Hex(cm.Marshal()))
			w.WriteHeader(http.StatusOK)
			w.Write(result)
		}
	}else {
		s.log.Printf("kzgsdk GenerateDataCommitAndProof Error: %s", err)
		w.WriteHeader(http.StatusBadRequest)
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
		s.log.Printf("kzgsdk GenerateDataCommitAndProof Error: %s", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	err = s.getSignatureAndSubmitToChain(cm,proof,preimage,commitmentByte)
	w.Header().Set("Content-Type", "application/octet-stream")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
	}else {
		w.WriteHeader(http.StatusOK)
	}
}

func (s *Server) getSignatureAndSubmitToChain(cm kzg.Digest,proof kzg.OpeningProof,preimage []byte,commitmentByte []byte) error {
	nodeGroupKey := common.HexToHash(s.config.NodeGroup)
	nameSpaceKey := common.HexToHash(s.config.Namespace)
	nodeGroup, err := s.storageManager.NODEGROUP(nil, nodeGroupKey)
	if err != nil {
		s.log.Printf("NODEGROUP----failed error:%s", err)
		return err
	}
	signatures := make([][]byte, 0)
	errList := make([]error, 0)
	timeNow := time.Now()
	timeOut := timeNow.Add(24 * time.Hour).Unix()
	sender := s.auth.From
	index, err := s.cmManager.Indices(nil, sender)
	length := len(preimage)
	result := make([]byte, 0)
	if bytes.Compare(commitmentByte,[]byte{}) == 0 {
		//without commit
		result = append(result, 1)
		result = append(result, cm.Marshal()...)
		s.log.Printf("cm string:%s", common.Bytes2Hex(result))
	}else {
		result = commitmentByte
	}
	s.log.Printf("transitStation is prepare getting signature commitment:%s", common.Bytes2Hex(cm.Marshal()))
	requestAddr,_ := s.storageManager.SortAddresses(nil,nodeGroup.Addrs)
	for _, add := range requestAddr {
		info, err := s.nodeManager.BroadcastingNodes(nil, add)
		if err != nil {
			continue
		}
		s.SignerClient, err = ethclient.Dial(info.Url)
		if err != nil {
			s.log.Printf("Getting connection with url:%s err:%s", info.Url, err)
			return err
		}
		s.log.Printf("transit Station is getting signature with url:%s", info.Url)
		claimedValue := proof.ClaimedValue.Marshal()
		sign, err := s.getSignature(sender, index.Uint64(), uint64(length), cm.Marshal(), preimage, nodeGroupKey, proof.H.Marshal(), claimedValue, uint64(timeOut), result)
		if err != nil {
			log.Println(err.Error())
			errList = append(errList, err)
			continue
		}
		signatures = append(signatures, sign)
	}
	if len(signatures) == 0 && len(errList) > 0 {
		s.log.Printf("send to signature failed  error:%s", errList[0])
		return errors.New("get signature failed")
	}

	commitData := contract.PairingG1Point{
		X: new(big.Int).SetBytes(cm.X.Marshal()),
		Y: new(big.Int).SetBytes(cm.Y.Marshal()),
	}

	addr := s.auth.From
	currentNonce,err := s.SenderClient.PendingNonceAt(s.ctx,addr)
	gasPrice, err := s.SenderClient.SuggestGasPrice(context.Background())
	if err != nil {
		s.log.Errorf("Failed to suggest gas price: %v",err)
		return errors.New("Failed to suggest gas price")
	}

	abiGen,err := abi.JSON(strings.NewReader(contractABI))
	if err != nil {
		return errors.New("load abi failed")
	}

	inner,err := abiGen.Pack(method, new(big.Int).SetInt64(int64(length)), new(big.Int).SetInt64(timeOut), nameSpaceKey, nodeGroupKey, signatures, commitData)
	if err != nil {
		return errors.New("abi pack transaction params failed")
	}
	tx := types.NewTransaction(currentNonce,common.HexToAddress(cmManagerAddress),new(big.Int).SetUint64(0),gasLimit,gasPrice,inner)
	// 签名交易
	chainID := big.NewInt(int64(s.config.ChainID))
	privateKeyECDSA, err := crypto.HexToECDSA(s.config.PrivateKey)
	if err ==  nil {
		signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKeyECDSA)
		if err == nil {
			s.log.Printf("SubmitCommitment tx Hash:%s", signedTx.Hash().Hex())
			err = s.SenderClient.SendTransaction(context.Background(), signedTx)
			if err == nil {
				receipt, err := bind.WaitMined(s.ctx, s.SenderClient, signedTx)
				if err != nil {
					errStr := fmt.Sprintf("cant WaitMined by contract address err:%s", err.Error())
					s.log.Println(errStr)
					return errors.New(errStr)
				}
				if receipt.Status == types.ReceiptStatusFailed {
					s.log.Errorf("transaction failed tx Hash:%s", signedTx.Hash().Hex())
					return errors.New("transaction failed")
				} else {
					s.log.Printf("transaction successful tx Hash:%s", signedTx.Hash().Hex())
				}
			}else {
				s.log.Errorf("Failed to send transaction: %v", err)
				return errors.New("Failed to send transaction")
			}
		}else {
			return err
		}
	}else {
		return err
	}
	return nil
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