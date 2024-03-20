# Overview of Repository

According to our claims in the paper [1], we made our source code for the ML training pipeline available in this repository. Our code that generates CSV files from PCAP files for classification model training & evaluation has been included in a commercial patent own by Canopus Networks Pty Ltd. Therefore, it will not be made publicly available in accordance with our research funding agreement.

### DataFormat

dataFormat folder is contains example csv files used to train machine learning and flow signature models on packet and flow attributes.

### Flow Signatures Extraction

Contains a script (PrimaryDomainFlowSignature.py) to generate primary domain byte signatures

Contains a script (TimeCriticalActivityDomainFlowSignature.py) to generate time critical domain byte signatures.

### Classification Model Training and Evaluation

Contains a system used to generated the packet and flow attributes used to build
our random forrest and neural networks models. An example attribute file is provided (AllAttributes.csv).

### Citing our Data and Code

```bibtex
@article{lyu2023metavradar,
  title={MetaVRadar: Measuring Metaverse Virtual Reality Network Activity},
  author={Lyu, Minzhao and Tripathi, Rahul Dev and Sivaraman, Vijay},
  journal={Proceedings of the ACM on Measurement and Analysis of Computing Systems},
  volume={7},
  number={3},
  pages={1--29},
  year={2023},
  publisher={ACM New York, NY, USA}
}
```
