up:
	docker-compose up -d --build

down:
	docker-compose down
	rm -f volumes/vol-keytabs/*.keytab