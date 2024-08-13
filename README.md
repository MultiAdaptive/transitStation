# transitStation
This is a transit station that is compatible with OP, EigenDA and other DA projects that can support MultiAdaptiveClient DA services

## Set config file 

You should set the config yaml file like this example :

**config.yaml**

```
server_address: ":8080"
private_key: "your_privatekey"
node_group: "your_node_group_here"
namespace: "your_namespace_here"
log_level: "info"  # 可以设置为 debug, info, warn, error, fatal
chainID: 11155111
url: "the eth net scan url "
```

## Make execution

Use the command ‘make’ on your terminal in the path of transitStation folder.

## How to use

This is a transit station that is compatible with OP, EigenDA and other DA projects that can support MultiAdaptiveClient DA services

Usage:
  transitStation [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  start       Start the relay server

Flags:
      --config string   config file (default is $HOME/.transitStationConfig.yaml)
  -h, --help            help for transitStation

Use "transitStation [command] --help" for more information about a command.

ps: 
```
cd transitStation/build
./transitStation --config $HOME/.transitStationConfig.yaml start
```


