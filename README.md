# Welcome to Safe URL

Safe URL is a flask web app that utilizes machine learning to check whether a URL is safe, unsafe, or non-existent. It uses a model trained on the UCI Phishing Dataset (https://archive.ics.uci.edu/ml/datasets/phishing+websites) along with the Random Forest Classifier algorithm to essentially predict the status of a URL.  This app includes a feature extractor which breaks an input URL into 30 distinct features for the model to analyze. 
The general feature categories include 

 - Address Bar Features
 - HTML/JS Features
 - Domain Features
 - Abnormalities
 
 

Each feature translates to either a 1 for safe, 0 for suspicious, or -1 for unsafe. The combination of each of these numeric values across the various features yields the overall URL status.

## Files

 - **app.py**: Default page of the app; handles routing
 - **featureExtraction.py**: Handles logic to extract all features and return a list containing the numeric equivalent of each feature
 -   **prediction.py**: Includes model training using Random Forest Classifier
 - **phishing.csv**: UCI Phishing Dataset
 
 -   **templates/index.html**: HTML page template
 -   **static/style.css**: Styling of HTML page


 
   
   


 

## Key Libraries

 - pandas
 - BeautifulSoup4
 - scikit-learn
 - googlesearch-python
 - urllib3
 - regex
 - python-whois

## Getting Started
Install all of the dependencies. For any libraries not installed, install manually. 
```sh
  pip install requirements.txt
  ```

Run app.py to bring up the webpage on localhost.
```sh
  python app.py
  ```
## Demo
![Image of Yaktocat](https://octodex.github.com/images/yaktocat.png)
