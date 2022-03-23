#### This script has been tested on Remnux only ####

#!/bin/sh

find . -maxdepth 5 -type f | \
	while read file; do \
		## working
		#echo $file; \
		x=$(file "$file"); \
		#echo "$x"; \
		case "$x" in \
			### the file itself
			*"$0"*) \
				;; \
			
			### message.txt
			*"message.txt"*) \
				echo "$x" + ".msg message"; \
				## can be parsed event nicer
				cat "$file" | grep "http"; \
				echo "\n\n";; \
			
			### PE32 (.NET) section
			*PE32*\.Net*) \
				## to implement stringsifter/rank_strings
				echo "$x" + "PE32 (.NET) found"; \
				echo "Running yara now..."; \
				yara -s -r -d VBA=1 ~/yararules/*.yara "$file"; \
				echo "yara result ends here..."; \
				echo "Check if there is a huge base64 payload"; \
				ilspycmd "$file" | base64dump.py -n 200; \
				echo "\n\n";; \
			
			### PE32 (others) section
			*PE32*) \
				echo "$x" + "PE32 found"; \
				### Note: running capa is quite intensive, you may wish to enable this in your environment
#				echo "Running capa now..."; \
#				capa "$file"; \
#				echo "capa result ends here..."; \
				echo "Running yara now..."; \
				yara -s -r -d VBA=1 ~/yararules/*.yara "$file"; \
				echo "yara result ends here..."; \
				### Note: running floss is quite intensive, you may wish to enable this in your environment
#				echo "Searching for interesting floss result..."; \
#				floss --no-static-strings "$file"; \
#				echo "Interesting floss result ends here..."; \
				echo "Searching for top interesting strings..."; \
				strings "$file" | rank_strings -s -l 10; \ #adjust this parameter as you deem
				echo "Interesting strings result ends here..."; \
				echo "\n\n";; \
			
			### Outlook message
			*Microsoft*Outlook*Message) \ 
				echo "$x" + "Microsoft Outlook message found"; \
				echo "\n\n";; \
			
			## Microsoft Documents
			*Microsoft*) \
				echo "$x" + "Microsoft Office document found"; \
				doc_name=$(echo $file | sed 's/^..//'); \
				echo "Running trid now..."; \
				trid "$doc_name"; \
				echo "trid result ends here.."; \
				echo "Running olevba now..."; \
				olevba "$file"; \
				oleout=$(olevba "$file"); \
				#echo $oleout; \
				echo "olevba result ends here..."; \
				case "$oleout" in \
					*Stomping*) \
						echo "stomping detected, running pcode2code now..."; \
						pcode2code "$file"; \
						echo "pcode2code result ends here..."; \
				esac; \
				echo "\n\n";; \
			
			### RTF
			*Rich*Text*Format*) \
				echo "$x" + "RTF found"; \
				echo "Running rtfdump.py now..."; \
				rtfdump.py "$file"; \
				echo "rtfdump result ends here..."; \
				echo "\n\n";; \
			
			### PDF section
			*PDF*document*) \
				echo "$x" + "PDF found"; \
				echo "Running pdf-parser (searching for risky keywords) now.."; \
				pdf-parser.py "$file" -O -a | grep "JS\|Javascript\|AcroForm\|XFA\|Launch\|EmbeddedFiles\|OpenAction\|AA\|URI\|SubmitForm"; \
				echo "pdf-parser search result for risky keywords ends here..."; \
				echo "Running pdf-parser (listing all URLs) now.."; \
				pdf-parser.py "$file" -O -k /URI; \
				echo "pdf-parser URL list result ends here..."; \
				echo "\n\n";; \
			
			### scripts [to be improved]
			*ASCII*text*) \
				echo "$x" + "clear text file found"; \
				echo "\n\n";; \
		esac \
	done
