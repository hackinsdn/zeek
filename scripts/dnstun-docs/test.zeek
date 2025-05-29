#execute on try.zeek.org

global a=0;

event zeek_init()
	{	
	
	local x: double;
	x=log2(10);
	print fmt("%f",x);
	
	local v1: vector of string;


	for (i in v1) {
		print fmt("%s", i);
	
	}
	local total: vector of count;
	total = vector(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
	local repeticao: vector of string;
	local palavra = "Palavra";
	local letras: vector of string;
	for (g in palavra){
		letras += g;
	} 
	for (j in letras) {
	
		print repeticao;


		if (|repeticao|==0){
		
			repeticao += letras[0];
		    total[0] +=1;
		}
		
		else{
		
		    print |repeticao|;
		    a=0;
			for (k in repeticao){
			
				if (repeticao[k]==letras[j]) {
					a=1;
					total[k]+=1;
					print fmt("exemplo1 %s %s %d",repeticao[k],letras[j], a);
					break;
				}
				else{
					print fmt("%s!=%s", repeticao[k],letras[j]);
				
				}
				}
			print fmt("OP %d", a);
			if (a==0){
			    repeticao += letras[j];
			    total[|repeticao|]+=1;

			    a=0;
			  }

	}
	
}

print repeticao;

for (i in total){
	if (total[i]!=0){
		print fmt("total[%d]=%d", i, total[i]);
		
	}

}

}


# palavra = (P,a,l,a,v,r,a)
# repeticao = (P,a,l,v,r)
# total = (1, 3, 1, 1, 1)
