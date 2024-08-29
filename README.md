# transitStation
This is a transit station that is compatible with OP, EigenDA and other DA projects that can support MultiAdaptiveClient DA services

## Git clone 

First of all,you should git clone this repository in your local place.

```
git clone https://github.com/MultiAdaptive/transitStation.git 
```
## Set config file 

You should set the config yaml file like this example :

**config.yaml**

```
server_address: ":8080"
private_key: "your_privatekey"
node_group: "your_node_group_here"
namespace: "your_namespace_here"
log_level: "info"  # the value can be debug, info, warn, error, or fatal
chainID: 11155111
url: "the eth net scan url "
```

## How can you get parames Nodegroup or Namespace

As a user who want to use this transitStation get the `NodeGroup` or `NameSpace` parames is necessory, you can use this Tools by this url: [multiAdaptive-cli](https://github.com/MultiAdaptive/multiAdaptive-cli).

NodeGroup: A group of broadcast nodes, with a specified minimum number of signatures required. The broadcast node is responsible for receiving and signing the data, and then forwarding the data.  
NameSpace: A group of storage nodes. Storage nodes store data for a long time.  

#### Build

  ```bash
    make build
  ```

#### Register NodeGroup
1. Run multiAdaptive-cli

```bash
./build/multiAdaptive-cli -privateKey="<your privateKey>" -advanced
```

2. Select Register NodeGroup.
3. Enter the list of broadcast node addresses, separated by commas.
4. Enter the minimum number of signatures.
5. Obtain the nodeGroupKey (used for advanced testing).

#### Register NameSpace
1. Run multiAdaptive-cli

```bash
./build/multiAdaptive-cli -privateKey="<your privateKey>" -advanced
```

2. Select Register NameSpace.
3. Enter the list of storage node addresses, separated by commas.
4. Obtain the nameSpaceKey (used for advanced testing).

## Make execution

Use the command ‘make’ on your terminal in the path of transitStation folder.

## How to use

This is a transit station that is compatible with OP, EigenDA and other DA projects that can support MultiAdaptiveClient DA services

```
Usage:
  transitStation [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  start       Start the relay server

Flags:
      --config string       config file (default is $HOME/.transitStationConfig.yaml)
      -h, --help            help for transitStation

Use "transitStation [command] --help" for more information about a command.

```

ps: 

This is an example for how to start the implementation procedures.

```
cd transitStation/build
./transitStation --config $HOME/.transitStationConfig.yaml start
```


