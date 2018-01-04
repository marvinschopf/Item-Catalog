# Item-Catalog - v148 - 01/04/2018
## Usage
1. Clone the repository to your computer
2. Install the requirements specified in ```requirements.txt```.
3. Replace the values in ```gh_client_secrets.json```, ```fb_client_secrets.json``` and ```client_secrets.json``` (Google) to their respective values from the **Api-Dashboards**.
4. Run the app using ```python3``` (on Port ```5000```)
5. Check if the database has been created (else run ```python(3) database_setup.py```)
6. Enjoy :)

## Demo
A demo can be found under [it‘s Heroku-Page](https://itemcatalog-marvnet.herokuapp.com).

## API-Endpoints
- ```/api/categories```: List all categories
- ```/api/category/[ID].json```: List a categorys meta information and items