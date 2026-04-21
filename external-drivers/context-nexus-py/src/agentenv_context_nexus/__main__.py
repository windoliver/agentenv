from agentenv_context_nexus.driver import NexusContextDriver
from agentenv_context_nexus.jsonrpc import JsonRpcServer


def main():
    JsonRpcServer(NexusContextDriver()).serve()


if __name__ == "__main__":
    main()
