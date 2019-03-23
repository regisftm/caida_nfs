#!/bin/bash

echo "Captura a ser processada = $1"

num_of_pkts=$(grep pkt $1 | wc -l)

echo "Número de pacotes da captura = $num_of_pkts"

sed -i 's/static const unsigned char //g' $1
sed -i 's/\/\*/\#/g' $1
sed -i 's/{/[/g' $1
sed -i 's/_1//g' $1
sed -i 's/_2//g' $1
sed -i 's/_3//g' $1
sed -i 's/};/]/g' $1
#sed -i 's///g' $1
sed -i 's/\[..\]//g' $1
sed -i 's/\[...\]//g' $1
sed -i 's/\[....\]//g' $1
sed -i 's/\[.....\]//g' $1

echo 'Captura convertida para python'

cp $1 ../.local/lib/python2.7/site-packages/captura.py

echo 'Captura carregada em site-packages como captura.py'

#./new_process_hash.py








