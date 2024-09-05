# Relic_BonehFranklin
Relic_BonehFranklin_Basic_and_Full_Ident

##Instructions for installing the RELIC toolkit on a Raspberry Pi 3 or 4 running ARM 64-bit architecture. 

##Prerequisites
Before you begin, ensure your system is up to date:
bash
sudo apt update && sudo apt upgrade -y



In order to run Boneh_Franklin_Basic and Boneh_Franklin_Full, please first install [Relic_Toolkit](https://github.com/relic-toolkit/relic).

Build instructions can be found in the [Wiki](https://github.com/relic-toolkit/relic/wiki/Building).


DFP_QNRES must be set to "on" in order for B12_P638 & B12_P446 curves to run.
DFP_PRIME sets specifies which curves can run each time. Relic must be build again in order to run a curve with different DFP_PRIME number.
 
