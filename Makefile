setup:
	docker compose up -d

shell:
	docker compose exec node1 bash

clean:
	docker compose down -v --rmi all --remove-orphans


# NOTE: Make sure you have your project files in the ./project directory
# Will run the autograder and place the results in ./results/results.json
run:
	docker pull eado0/reliability-is-essential
	docker run --rm -v ./project:/autograder/submission/project -v ./results:/autograder/results eado0/reliability-is-essential /autograder/run_autograder && cat results/results.json

# In case you want to run the autograder manually, use interactive
interactive:
	docker pull eado0/reliability-is-essential
	docker run --rm -it -v ./project:/autograder/submission/project -v ./results:/autograder/results eado0/reliability-is-essential bash

# These are for our usage; don't worry about them
build:
	docker build -t reliability-is-essential .
push:
	docker tag reliability-is-essential eado0/reliability-is-essential
	docker push eado0/reliability-is-essential
runl:
	docker run --rm -v ./project:/autograder/submission/project -v ./results:/autograder/results reliability-is-essential /autograder/run_autograder && cat results/results.json
interactivel:
	docker run --rm -it -v ./project:/autograder/submission/project -v ./results:/autograder/results reliability-is-essential bash