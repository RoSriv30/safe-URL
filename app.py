# import libraries
import numpy as np
from flask import Flask, request, jsonify, render_template
import pickle

# Initialize the flask App
app = Flask(__name__)
model = pickle.load(open('model.pkl', 'rb'))


# default page of our web-app
@app.route('/')
def home():
    return render_template('index.html')


# To use the predict button in our web-app
@app.route('/predict', methods=['POST'])
def predict():
    testArr = [1050, 0.3542857143, 1938, 8287, -4.001514249, 1, 0, 0, 62, 0, 0, 0, 0, 0, 0, 1, 1050, 372, 2.822580645,
               0, 192]

    """
    For rendering results on HTML GUI
    """
    # int_features = [float(x) for x in request.form.values()]
    # final_features = [np.array(int_features)]
    # prediction = model.predict(final_features)

    output = model.predict([testArr])

    return render_template('index.html', prediction_text='URL is :{}'.format(output))


if __name__ == "__main__":
    app.run(debug=True)
