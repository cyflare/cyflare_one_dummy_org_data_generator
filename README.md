# Cyflare Dummy Org Data Generator

Python project for generating demo data for a dummy organization and save it in database for alert stats, tickets, xdr and ecr.

## Examples of Usage

* For only creating Tickets on current day:
```commandline
python src/main.py generate --create_tickets true --number_of_elements_per_date 10
```

* For only creating Alert Stats on current day:
```commandline
python src/main.py generate --create_alertstats true --number_of_elements_per_date 10
```

* For creating data for them all on current day:
```commandline
python src/main.py generate --create_all true --number_of_elements_per_date 10
```

* For creating Alert Stats on specific date range:
```commandline
python src/main.py generate --create_alertstats true --number_of_elements_per_date 10 --start_date 20240801 --end_date 20240831
```

* For creating Tickets on specific date range:
```commandline
python src/main.py generate --create_tickets true --number_of_elements_per_date 10 --start_date 20240801 --end_date 20240831
```

* For creating data for them all on specific date range:
```commandline
python src/main.py generate --create_all true --number_of_elements_per_date 10 --start_date 20240801 --end_date 20240831
```



<br>
* By default, it will use the current date as default when no start/end date is provided.
<br>
* All records will be created with the run time in UTC (with provided dates or default current date).
<br>
* All records will be created for the customer: **Cyflare Demo Generated** as setup in the settings.  To use the data in ONE Portal assign that customer to the organization's chronicle_name field.
