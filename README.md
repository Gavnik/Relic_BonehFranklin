# Relic_BonehFranklin
Relic_BonehFranklin_Basic_and_Full_Ident

##Instructions for installing the RELIC toolkit on a Raspberry Pi 3 or 4 running ARM 64-bit architecture. 

## Prerequisites

Before you begin, ensure your system is up to date:

```bash
sudo apt update && sudo apt upgrade -y
```

Install necessary dependencies:

```bash
sudo apt-get install -y git cmake build-essential libgmp-dev libssl-dev libffi-dev libboost-all-dev
```

## GMP Installation

RELIC requires GMP (GNU Multiple Precision Arithmetic Library). Here's how to install it:

1. Download GMP:
```bash
wget "https://gmplib.org/download/gmp/gmp-6.2.1.tar.lz"
```

2. Install lzip and extract:
```bash
sudo apt-get update -y && sudo apt-get -y install lzip 
tar --lzip -xf gmp-6.2.1.tar.lz 
```

3. Configure, make, and install:
```bash
cd gmp-6.2.1/
./configure
make
make check
sudo make install
```
## PBC (Pairing-Based Cryptography) Library Installation

To install the PBC library:

1. Download and extract:
```bash
wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz
tar -xzf pbc-0.5.14.tar.gz
```

2. Install dependencies and build:
```bash
sudo apt-get install build-essential flex bison libgmp3-dev libssl-dev 
cd pbc-0.5.14
./configure
make
sudo make install
```

## RELIC Installation

Now, let's install RELIC:

1. Clone the repository:
```bash
git clone https://github.com/relic-toolkit/relic.git
cd relic
mkdir build
cd build
```

2. Configure RELIC:
```bash
cmake .. -DALLOC=AUTO -DARCH=A64 -DWSIZE=64 -DCHECK=off -DFP_PRIME=638 -DFP_QNRES=off -DEP_METHD="PROJC;LWNAF;COMBS;INTER"
```

Note: Adjust parameters as needed. For example, `-DFP_PRIME` defines which curves can be implemented.

3. Build and install:
```bash
make
sudo make install
```

## Environment Setup

Add the following lines to your `~/.bashrc` file:

```bash
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
export PATH=$PATH:/home/pi/.local/bin
export PATH=~/.local/lib/python3.9/site-packages:$PATH
export PATH=~/.local/lib/python3.9/site-packages/pyrelic:$PATH
export PATH=/home/pi/pbc-0.5.14:$PATH
```

Remember to source your `.bashrc` or restart your terminal after making these changes.

## Compiling C Programs with RELIC

To compile a C program that uses RELIC:

```bash
gcc -o your_program your_program.c -lrelic -I/usr/local/include/relic -L/usr/local/lib/
```

If your program includes `math.h`, add `-lm` at the end of the compilation command.

## Troubleshooting

If you encounter issues or need to reconfigure RELIC, you can clean the build and start over:

```bash
cd /path/to/relic/build
make clean
cd ..
rm -rf build
```

Then, recreate the build directory and follow the installation steps again.

## Note on BN_P638 Curve

For using the BN_P638 curve, special modifications are required. Refer to the RELIC repository's BN_P638 branch for necessary changes in specific files.

## Contributing

Contributions to improve this guide are welcome. Please submit a pull request or open an issue for any suggestions or corrections.

##Notes

In order to run Boneh_Franklin_Basic and Boneh_Franklin_Full, please first install [Relic_Toolkit](https://github.com/relic-toolkit/relic).

Build instructions can be found in the [Wiki](https://github.com/relic-toolkit/relic/wiki/Building).

DFP_QNRES must be set to "on" in order for B12_P638 & B12_P446 curves to run.
DFP_PRIME sets specifies which curves can run each time. Relic must be build again in order to run a curve with different DFP_PRIME number.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details. 
