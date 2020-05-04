#!/bin/bash
#Katalog - trzeba te¿ ustawic w linii zaczynajacej sie od find!!!
katalog_roboczy="./";

#echo $katalog_roboczy;
echo "" >  $katalog_roboczy/klasy.txt

#find ./0x0* -exec bash -c '(echo "$1 sesja"; hexdump -C "$1") >> ${katalog_roboczy}/klasy.txt' test {} \;
echo "$1 sesja" > $katalog_roboczy/klasy.txt
hexdump -C "$1" >> $katalog_roboczy/klasy.txt
sed 's/^0.......//g'  $katalog_roboczy/klasy.txt | sed 's/..|.*|//g' >  $katalog_roboczy/klasy2.txt
tr '\n' ' ' <  $katalog_roboczy/klasy2.txt | sed 's/\.\//\n /g'|sed 's/ //g' | sed 's/sesja/ /g' >  $katalog_roboczy/klasy3.txt
perl $katalog_roboczy/analiza_gero.pl

#rm -rf  $katalog_roboczy/klasy.txt
#rm -rf  $katalog_roboczy/klasy2.txt
#rm -rf  $katalog_roboczy/klasy3.txt
