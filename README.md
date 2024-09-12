# Cyflare Dummy Org Data Generator

Python project for generating demo data for a dummy organization and save it in database for alert stats, tickets, xdr and ecr.

## Examples of Usage

* For only creating Tickets:
```commandline
python src/main.py run --create_tickets True --number_of_elements 10
```

* For only creating Alert Stats:
```commandline
python src/main.py run --create_alertstats True --number_of_elements 10
```

* For creating data for them all:
```commandline
python src/main.py run --create_all True --number_of_elements 10
```

<br>

All records will be created for the customer: **Cyflare Demo Generated** as setup in the settings.<br>  
To use the data in ONE Portal assign that customer to the organization's chronicle_name field.