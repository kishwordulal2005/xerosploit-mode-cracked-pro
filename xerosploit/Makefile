all:

clean:

install:
	chmod 755 banner.py
	chmod 755 install.py
	chmod 755 run.sh
	chmod 755 xerosploit.py
	mkdir -p $(DESTDIR)/opt/xerosploit/
	mkdir -p $(DESTDIR)/usr/share/doc/xerosploit/
	mkdir -p $(DESTDIR)/opt/xerosploit/tools/files
	mkdir -p $(DESTDIR)/opt/xerosploit/tools/log
	mkdir -p $(DESTDIR)/opt/xerosploit/tools/bettercap2/tmp
	mkdir -p $(DESTDIR)/usr/bin/
	cp banner.py $(DESTDIR)/opt/xerosploit/
	cp install.py $(DESTDIR)/opt/xerosploit/
	cp LICENSE $(DESTDIR)/opt/xerosploit/
	cp Makefile $(DESTDIR)/opt/xerosploit/
	cp README.md $(DESTDIR)/opt/xerosploit/
	cp README.md $(DESTDIR)/usr/share/doc/xerosploit/
	cp requirements.txt $(DESTDIR)/opt/xerosploit/
	cp run.sh $(DESTDIR)/opt/xerosploit/
	cp run.sh $(DESTDIR)/usr/bin/xerosploit
	chmod 755 $(DESTDIR)/usr/bin/xerosploit
	cp xerosploit.py $(DESTDIR)/opt/xerosploit/
	cp -r tools $(DESTDIR)/opt/xerosploit/
	echo 0 > $(DESTDIR)/opt/xerosploit/tools/files/iface.txt
	echo 0 > $(DESTDIR)/opt/xerosploit/tools/files/gateway.txt
	touch $(DESTDIR)/opt/xerosploit/tools/log/.keep
	touch $(DESTDIR)/opt/xerosploit/tools/bettercap2/tmp/.keep
	

