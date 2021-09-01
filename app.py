# import libraries

from flask import Flask, request, jsonify, render_template
import pickle

# Initialize the flask App
import featureExtraction

app = Flask(__name__)
model = pickle.load(open('model.pkl', 'rb'))


# default page of our web-app
@app.route('/')
def home():
    return render_template('index.html')


# To use the predict button in our web-app
@app.route('/predict', methods=['POST'])
def predict():

    """
    For rendering results on HTML GUI
    """
    url = [x for x in request.form.values()]
    print(url[0])
    testArr = featureExtraction.UrlFeaturizer(url[0]).run()
    # testArr = [1, 0, 1, 1, 1, 1, 1, -1, -1, None, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, 1, -1, -1, -1, -1, 1]


    result = 'SAFE'
    if testArr == 'Non-Existent':
        result = 'Non-Existent'
        return render_template('index.html', prediction_text=' {}'.format(result))

    for i in range(len(testArr)):
        if testArr[i] == None:
            testArr[i] = -1
    print(testArr)
    output = model.predict([testArr])
    if output[0] == -1:
        result = 'UNSAFE'


    # return render_template('index.html', prediction_text=' {}'.format(result))
    return render_template('index.html', prediction_text=' {}'.format(result))
    # return render_template('index.html', prediction_text=' {}'.format(testArr))


if __name__ == "__main__":
    app.run(debug=True)
