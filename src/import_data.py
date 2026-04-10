"""
All imports for the ATLAS project.
"""

# Standard library
import os
import warnings
# remove warnign for zip file duplicate
warnings.filterwarnings("ignore",category=UserWarning,module="zipfile",message="Duplicate name:.*")
warnings.filterwarnings("ignore",category=FutureWarning)

import zipfile
import sys
import re
import glob
import ast
import csv
import yaml
import bz2
import json
import asyncio
import logging
import random
import whois
import requests
import socket
import math
import dns.resolver
import shodan
from typing import List, Dict, Union, Any, Optional, Tuple, Literal
import argparse
from collections import defaultdict, Counter
import inspect
from multiprocessing import Pool
from concurrent.futures import ThreadPoolExecutor
from time import monotonic
from pandarallel import pandarallel
import timeit
import subprocess
import threading
import numpy as np
import time
from urllib.request import urlopen
from itertools import islice
import multiprocessing
from urllib.parse import urljoin
from multiprocessing import Process
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout
from scipy.stats import fisher_exact
from playwright_stealth import Stealth

import time
import numpy as np

# Pandas Dataframe
import pandas as pd

# Playwright (Web automation)
from playwright.async_api import (
    async_playwright,
    Browser,
    BrowserContext,
    Page,
    Request,
    Response,
    Frame,
    ElementHandle,
    TimeoutError as PlaywrightTimeoutError
)

# Progress bar
from alive_progress import alive_bar

# Timestamp
from datetime import datetime, timedelta

# Our own stuffs
from configs import *
from logger import logger

from atlas.CookieBanner import *
from atlas.PageContextClassifier import *
from atlas.FedCMDetector import *
from atlas.Dom import *
from atlas.IFrameHandler import *
from atlas.NetworkAnalyser import *
from atlas.LocalStorageAnalyser import *
from atlas.ShadowDom import *
from atlas.Authentication import *
from atlas.Interaction import *
from atlas.MultiStepLogin import *
from atlas.ConfidenceScore import *
from atlas.Classification import *
from atlas.OTPDetection import *
from atlas.PasskeyTrigger import *
from atlas.ProcessSite import *
from atlas.Atlas import *

from challenge.AnalyseFidoChallenge import *
from challenge.ChallengeCaptureSite import *
from challenge.RunChallengeCapture import *
from challenge.ChallengeUtils import *

from analysis.Filtering import *
from analysis.StatsUtils import *
from analysis.ClosedShadowDOMValidator import *
from analysis.GroundtruthAnalysis import *
from analysis.ScrapingAnalysis import *
from analysis.ChallengeCaptureAnalysis import *
from analysis.EthicsAnalysis import *
from analysis.AnalyseAtlas import *
from analysis.URLFiltering import *

from utils import *
