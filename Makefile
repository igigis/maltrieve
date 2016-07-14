DOCKER_TAG = harryr/maltrieve:latest

all: 
	@echo "Please make one of: egg, docker, shell"

egg:
	python setup.py bdist_egg

docker:
	docker build -t $(DOCKER_TAG) .
	docker run -ti $(DOCKER_TAG)
