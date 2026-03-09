# DataFilter

## Contents

1. [About project](#About-project)
2. [Project functionality](#Project-functionality)
3. [Repository structure](#Repository-structure)
4. [Expected behavior](#Expected-behavior)
5. [Full documentation](#Full-documentation)
6. [Contacts](#Contacts)

---

## About project

**DataFilter** is a single-file library written in Python used for:

1. Checking whether data includes SQLi techniques
2. Providing detailed information about the safety of data
3. Helping to temporarily/permanently block potential attackers, improving safety

**The core idea of the project** is to improve the safety of apps that use sql databases and informing the service about detections so it can take action

DataFilter **is not able** to fully protect service, input escaping is still required and highly recommended!

---

## Project functionality

function **strSQLICheck**

- Analyzes the provided data using basic-heuristic and pattern-based strategy
- Generates a report upon return that includes useful and overall safety information about provided data

---

## Repository structure

Below the repository directory tree is provided (without cache files like `__pycache__`):

```
    DataFilter
    ├── docs
    │   └── docs.odt
    ├── testapps
    │   ├── appSQLInoFiltering
    │   │   ├── app.py
    │   │   ├── database.db
    │   │   └── requirements.txt
    │   └── appSQLIwithFiltering
    │       ├── app.py
    │       ├── database.db
    │       ├── DataFilter.py
    │       └── requirements.txt
    ├── DataFilter.py
    ├── LICENCE
    └── README.md


```

- **`testapps`** — 2 test apps without input escaping: **appSQLInoFiltering** with DataFilter not being used, **appSQLIwithFiltering** with DataFilter used; start them with commands below, ensure you are in the app’s directory
```
python -m pip install --upgrade pip
python -m pip install requirements.txt
python app.py
``` 
After that use any SQLi testing utility you like (for example sqlmap)

---

## Expected behavior

- **Normal user**: interacts with service without any problem, may sometimes trigger filter, for example by using ' or " in password when registering
- **Attacker**: tries to use SQLi -> filter detects SQLi usage -> (programmer defined behavior) service takes action (for example temporary ban if 3+ SQLi attempts detected)

---

## Full documentation

You can find full documentation in docs.odt file [here](https://github.com/Mavment/DataFilter/tree/master/docs)

Full documentation includes expected behavior of data checker, strategies used, report structure and a lot more!

---

## Contacts

- It’s well-known that no solution is perfect and DataFilter is not an exception, you may ask me freely if you have any questions/suggestions, I'll answer whenever I'll be free (usually not more than 1 business day)

Thanks for using **DataFilter**!