# Cyflare Dummy Org Data Generator

Python project for generating demo data for a dummy organization and save it in database for alert stats, tickets, xdr and ecr.

## Examples of Usage

* For only creating Tickets on current day:
```commandline
python src/main.py generate --create_tickets True --number_of_elements_per_date 10
```

* For only creating Alert Stats on current day:
```commandline
python src/main.py generate --create_alertstats True --number_of_elements_per_date 10
```

* For creating data for them all on current day:
```commandline
python src/main.py generate --create_all True --number_of_elements_per_date 10
```

* For creating data for them all on specific date range:
```commandline
python src/main.py generate --create_all True --number_of_elements_per_date 10 --start_date 20240801 --end_date 20240831
```

<br>
All records will be created with the run time in UTC (with provided dates or default current date).

All records will be created for the customer: **Cyflare Demo Generated** as setup in the settings.<br>
To use the data in ONE Portal assign that customer to the organization's chronicle_name field.
