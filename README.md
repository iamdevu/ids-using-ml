# description
- a brief on what has been done in what component file
### data preprocessing and model training (training_grid_cv10_test.ipynb)
- the dataset used is created concatenating an attack dataset & a bonafide dataset
- attack dataset conatains several types of port probes via many well-know tools
- bonafide dataset contains normal traffic instances
- dataset has undergone preprocessing and due reasons are given
- feature selection has been done and a set of remaining features were finalized 
- 8 classifiers including one Multi-layer perceptron have been used
- Grid search alongwith 10-fold cross validation has been used to
  - train classifiers and evaluate the model with best hyperparaters
  - get the best set of hyperparameters to use in model generation phase

### model generation ( model_generation_cv10_whole.ipynb)
- classifiers have been initialized with best hyperparameters
- classifier models have been trained on whole dataset
- models, now ready to be used, have been saved

### model deployment (ids_app_view.py)
- this script captures tcp packets on pre-specified net interface (changable)
- gets the features that were finalized in earlier phase from the captured sample
- classifies the captured sample using user-specified ML model
