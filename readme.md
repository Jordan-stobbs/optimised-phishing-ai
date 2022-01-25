Files included (or would be with space allowance)
* data.db - database used during run time
* Database/CutDown.db - The final cut down database
* Database/FullDatabase.db - The final full database
* dataCollection.ipynb - The jupyter notebook version of the script that collects the data
* dataCollection.py - The python version of the script that collects the data, untested, should only be
 		used if unable to use the previous file
* Datasets/results.csv - raw data results
* Datasets/top-1m.csv - top 1m sites supplied by alexa
* Datasets/urlset.csv - a phishing/genuine URL dataset used in TLD comparisons.
* detectionModel.pkl - the final AI model.
* GAFO.py - The algorithm used for GAFO, adapted slighlty by me but mostly taken from source in file
* GAFO.ipynb - The algorithm used for GAFO, in python format
* phishingDetector.ipynb - The experimentation script used for trying different AI models.
* phishingDetector.py - The experimentation script used for trying different AI models, python version, untested,
	 should only be used if unable to use the previous file
* TestLogs/TestFiles - Files used for testing as stated in the various test logs
* TestLogs/MLTests.ods - File indicating tests and results for the phishingDetector script
* TestLogs/DataCollectionTests.ods - File indicating tests and results for the dataCollection script
* TestLogs/DatabaseTests.ods - File indicating tests and results for the database.
* top-1m.csv - top 1m sites supplied by alexa used in runtime.


Since initial creation, a second dataset and model was created, these are data2.db and detectionModel2.pkl

Installation instructions
This version was created using anaconda version 2019.10, newer versions should be compatible, anaconda can be found here https://www.anaconda.com/

Assuming anaconda is used, the following pip commands will need to be run:
* pip3 install beautifulsoup4
* pip3 install HTMLParser
* pip3 install hyperopt
* pip3 install mealpy
* pip3 install pyswarms
* pip3 install selenium
* pip3 install tldextract

Selenium also requires the installation of a web driver, for this project firefox was used, however any should work. Details on installation can be found here https://www.selenium.dev/downloads/

There are 2 scripts that may require running.
Firstly data collection - Can be run from start to finish.

Secondly phishingDetector - Cells should be run up to the indicated point.
The comment "CELLS UP TO HERE ARE NEEDED TO RUN, THE REST ARE FOR SPECIFIC AI ALGORITHMS/OPTIMISATION ALGORITHMS" indicates a stopping point. From here only models that are being tested should be run. Also note that these models do take a long time to run.
