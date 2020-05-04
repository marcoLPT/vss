#!/usr/bin/perl

#Zmienne do ustawinia
my $HEADEND="0";
my $plik_do_analizy="./klasy3.txt";

#my $file = $ARGV[0];
#my $string = "";
#
#{
#  local $/ = undef;
#  open FILE, "$file" or die "Couldn't open file: $!";
#  binmode FILE;
#  $string = <FILE>;
#  close FILE;
#}
#
#print "x", unpack("H*", $string), "\n";




my %sesje;
my %dlugosc;
my %XID;
my %CI;
my %SOID;
my %indx_key;
my %conf;
my %gener;
my %CWP_FSR2;
my %CWP_FSR3;
my %CWP_FSR5;
my %klasy2;
my %klasy3;
my %klasy5;

sub print_x {
	#print shift;

}


open FILE, $plik_do_analizy or die $!;
while (<FILE>) {
	print_x( "START****************************************\n");
	my $tmp1 = $_;
	@Tablica = split( /\s+/, $tmp1);
	$Tablica[0] =~ s/.stat$//;
	if( length($Tablica[1])> 0 ) {
	$sesje{$Tablica[0]}= $Tablica[1];
	$dlugosc{$Tablica[0]}=substr $Tablica[1], 0, 4;
	$gener{$nazwa}='';
	$klasy2{$nazwa}='';
	$klasy3{$nazwa}='';
	$klasy5{$nazwa}='';
	print "$sesje{$Tablica[0]}\n";
	print "$dlugosc{$Tablica[0]}\n";

	my $pozycja=4;
	my $dl = length($Tablica[1]);
	while ($pozycja < $dl){
		 $pozycja = analiza_tagu($pozycja, $Tablica[1],$Tablica[0]);
		} 
	}
	}

drukuj();


sub analiza_tagu {
        my($pozycja,$sesja,$nazwa) = @_;
	my $tag = substr($sesja,$pozycja,2);
	my $length = substr($sesja,$pozycja+2,2);
	my $dec_length = hex($length);
	my $poz_ret=$pozycja+4+$dec_length*2;
	my $wartosc= substr($sesja,$pozycja+4,$dec_length*2);
	print_x "POZYCJA: $pozycja \n";
	print_x "SESJA: $sesja \n";
	print_x "TAG: $tag \n";
	print_x "LEN: $length \n";
	print_x "DLUGOSC DEC: $dec_length \n";
	print_x "WARTOSC: $wartosc \n";	
	print_x "POZYCJA2: $poz_ret\n";
	
	if ($tag == 10) {
		$XID{$nazwa}=hex($wartosc);		
	}
	elsif ($tag == 13) {
		$CI{$nazwa}=$wartosc;
       }
        elsif ($tag == 14) {
		$SOID{$nazwa}=$wartosc;
       }
       
        elsif ($tag == 17) {
		analiza_szyfrowania($wartosc, $nazwa);
       }
	elsif ($tag == 19) {
	}
       
	elsif ($tag eq ' ' ) {

	}
       	else {
		print_x "analiza tagu: NIEZNANY TAG:  $tag  w sesji: $nazwa \n";
	}

	
	return $poz_ret;
       }

		


sub analiza_szyfrowania {
        my($szyfrowanie,$nazwa) = @_;
	my $szyfrowanie_len = length($szyfrowanie);
	print_x "SZYFROWANIE: $szyfrowanie \n";
	$tag_value = substr($szyfrowanie,0,2);
	$header_length =hex(substr($szyfrowanie,2,2));
	$header=substr($szyfrowanie,4,$header_length*2);
	my  $config="";

	print_x "NAGLOWEK_DL: $header_length\n";	
	print_x "NAGLOWEK: $header\n";
	print_x "TAGXXXX: $tag_value\n";
	
	#sprawdzenie czy nie zaczyna sie od razu od klas szyfrowania
	
	if ( $tag_value eq 'e2' or $tag_value eq 'e0' ){
		 print_x "TAGOWAN: $tag_value\n";
		 $config="classic";
		 $conf{$nazwa}= $config;
		 $indx_key{$nazwa}="N/A";
		 $gener{$nazwa}="ALL_CARD";
		 $generacja=5;
		 $pozycja=0;
                 while ($pozycja<$szyfrowanie_len) {
                                $pozycja =      analiza_tagu_syfr($szyfrowanie,$pozycja,$nazwa,$generacja);
		}

	}
	elsif  ( $tag_value eq '90' )  {
		if ($header_length==3) {
			$config="classic";
			#print_x "KONFIGURACJA: $config \n";
		 	$conf{$nazwa}= $config;	
			$index_key=hex(substr($header,4,2));
		
        	        $indx_key{$nazwa}=$index_key;
			$gener{$nazwa}="ALL_CARD";
			$generacja=2;
			$pozycja=10;
		        while ($pozycja<$szyfrowanie_len) {
				$pozycja =      analiza_tagu_syfr($szyfrowanie,$pozycja,$nazwa,$generacja);
		        }
		
		}
		elsif ($header_length==7) {
		#Dodanie sprawdzenia czy PC3.0 czy PC5.0
		       $config="multigeration";
                       $conf{$nazwa}= $config;
		       $index_key=hex(substr($header,6,2));
	        	$indx_key{$nazwa}=$index_key;
		       $generacja=substr($header,8,6);
		       if ($generacja eq '0577ff') {
				if (length($gener{$nazwa})>0) {
					$gener{$nazwa}="$gener{$nazwa}/PC3.0";
				}
				else {
					$gener{$nazwa}="PC3.0";
				}
				$generacja=3;
	       	}
		       elsif ($generacja eq '070cff') {
				if (length($gener{$nazwa})>0) {
					$gener{$nazwa}="$gener{$nazwa}/PC5.0";
				}
				else {
					$gener{$nazwa}="PC5.0";
				}	
				$generacja=5;
	       		}
		       else {
				print_x "NIEZNANY TAG GENERACJI: $generacja\n";
				 $gener{$nazwa}="$gener{$nazwa}/NIEZNANA";
				 
	       	}
		       $pozycja=18;
		       while ($pozycja<$szyfrowanie_len) {
				$pozycja =      analiza_tagu_syfr($szyfrowanie,$pozycja,$nazwa,$generacja);
	       	}
		}
		else {
			print_x "Nieznany naglowek o dlugosci: $header_length!!!\n";
		}
	}
	
}


sub analiza_tagu_syfr {
	print_x "ANALIZA TAGU SZYFR\n";
        my($sesja,$pozycja,$nazwa,$generacja) = @_;
	my $tag = substr($sesja,$pozycja,2);
	my $length = substr($sesja,$pozycja+2,2);
	my $dec_length = hex($length);
	my $poz_ret=$pozycja+4+$dec_length*2;
	my $wartosc= substr($sesja,$pozycja+4,$dec_length*2);
	print_x "SESJA: $sesja \n";
	print_x "TAG: $tag \n";
	print_x "LEN: $length \n";
	print_x "DLUGOSC DEC: $dec_length \n";
	print_x "WARTOSC: $wartosc \n";	
	print_x "POZYCJA2: $poz_ret\n";
	
	if ($tag eq "e0") {
		print_x "e0 - FSR lub CWP\n";
		if ($wartosc eq '20') {
			$cwp="FSR";
			
		}
		elsif ($wartosc eq '2002'){
			$cwp="FSR + HW_CWP";
		}
		elsif ($wartosc eq '0002'){
                        $cwp="HW_CWP";
		}
		elsif ($wartosc eq '0001'){
                        $cwp="SOFT_CWP";
                }
		elsif($wartosc eq '0f'){
		                $cwp="CSA5";
		}
		else {
			$cwp="NIEZNANY TAG: $wartosc";
		}
		print_x "$cwp \n";


		if ($generacja == 2) {
			$CWP_FSR2{$nazwa}=$cwp;			

		}
		elsif ($generacja == 3) {
			$CWP_FSR3{$nazwa}=$cwp;

		}
		elsif ($generacja ==5) {
			$CWP_FSR5{$nazwa}=$cwp;
		}
		else {
			print_x "NIEZNANA GENERACJA\n";
		}
		
							
		
	}
	elsif ($tag eq 'e2') {
	        print_x "e2 - KLASA SZYFROWANIA\n";
	        print_x "KLASA HEX: $wartosc \n";
		$klasa=hex($wartosc);
		print_x "KLASA DEC: $klasa \n";
		if ($generacja ==2) {
			$klasy2{$nazwa}="$klasy2{$nazwa}-$klasa";		

		}
		elsif ($generacja == 3) {
			$klasy3{$nazwa}="$klasy3{$nazwa}-$klasa";

		}
		elsif ($generacja ==5) {
			$klasy5{$nazwa}="$klasy5{$nazwa}-$klasa";
		}
		else {
			print_x "NIEZNANA GENERACJA\n";
		}
	}
	return  $poz_ret;
}


sub drukuj {

#print "*************************FUNKCJA DRUKUJACA*******************\n";
@lista_sesji = keys(%sesje);

  
  print "timestamp;CAS_ID;sesja;head_end;XID;CI;SOID;INDEX_KEY;KONFIGURACJA;GENERACJE;FSR_CWP_PC2.6;FSR_CWP_PC3.0;FSR_CWP_PC5.0;klasy2.6;klasy3.0;klasy5.0;\n";
 foreach my $p (@lista_sesji )
    {

  	($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime(time);
	$year=$year+1900;
	$mon-$mon+1;	
	$tmp =$p ;
	$tmp =~ s/\./\;/;
	my $kl26 =  sortuj($klasy2{$p});
	my $kl30 =  sortuj($klasy3{$p});
	my $kl50 =  sortuj($klasy5{$p});
	my $now = sprintf("%04d-%02d-%02d %02d:%02d:%02d", $year, $mon+1, $mday, $hour, $min, $sec);
	 
	print "$now;";
	print "$tmp;";
	print "$HEADEND;";
	print "$XID{$p};";
	print "$CI{$p};";
	print "$SOID{$p};";
	print "$indx_key{$p};";
	print "$conf{$p};";
	print "$gener{$p};";
	print "$CWP_FSR2{$p};";
	print "$CWP_FSR3{$p};";
	print "$CWP_FSR5{$p};";
	print "$kl26;";
	print "$kl30;";
	print "$kl50";
	
	print "\n";
	
	my @values = split('-', $klasy2{$p});
	 my @sorted_words = sort { $a <=> $b }@values;
	 $klass='';
	 foreach my $val (@sorted_words) {
	     $klass=$klass."$val-";
	       }
    }
}


sub sortuj {
	 my($wart) = @_;
	 my @values = split('-', $wart);
	 my @sorted_words = sort { $a <=> $b }@values;
	 $klass='';
	 foreach my $val (@sorted_words) {
	     $klass=$klass."$val-";
	       }
		  return $klass;
}
