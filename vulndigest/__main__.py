import sys
from vulndigest_cli import VulnDigestCLIWrapper

def main():
    cli_wrapper = VulnDigestCLIWrapper(sys.argv)
    cli_wrapper.execute()

if __name__ == "__main__":
    main()