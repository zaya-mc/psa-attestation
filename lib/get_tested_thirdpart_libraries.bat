
if not exist QCBOR git clone https://github.com/laurencelundblade/QCBOR.git
REM psa-arch-tests is a 3rd party library and we cannot guarentee any modification without testing it, so we checkout a tested version
cd QCBOR
git checkout v1.2

cd ..

REM NOTE : We dont close t_cose for now
REM if not exist t_cose git clone https://github.com/laurencelundblade/t_cose.git
REM cd t_cose
REM git checkout v1.1.2
