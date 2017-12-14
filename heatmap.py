
# coding: utf-8

# # Project 3


# Open your Anaconda prompt and enter the following:
#     pip install python-twitter
# 
# See documentation here
# https://github.com/bear/python-twitter 
# https://python-twitter.readthedocs.io/en/latest/
# 
# ***Issues may occur if other twitter libraries exist on your machine***
# 
# Attached you will find my secret information. I trust the TAs! 

# In[1]:

import twitter 
#go to apps.twitter.com to get the key and secret info

tw = twitter.Api(consumer_key='XXXX',
				consumer_secret='XXXX',
				access_token_key='XXXX',
				access_token_secret='XXXX')

#run the below print command to make sure the credentials worked 
print(tw.VerifyCredentials())


# Now that we have confirmed that the API has acknowledged and authenticated our account we can begin to look for specific things. I want to look on FireEye's two accounts, @FireEye and @FireEye_Intel and look at the last 200 tweets to see how many mentions of APTs they have in their tweets. I then want to count them and determine which have been the most published about. That's why I set the count to the max limit of 200 

# In[3]:

#GetUserTimeline() uses **kwargs for screen_name=[str] and count = none so it only gets from current timeline w/ max  = 200 

FEtweets = tw.GetUserTimeline(screen_name='FireEye', count = 200)
FEItweets = tw.GetUserTimeline(screen_name='FireEye_Intel', count = 200) 

print (FEtweets, '\n', FEItweets)      


# So that's pretty messy and pretty hard to discern anything from so I'll create a list so that among these 200 tweets I want First: just the text and none of the meta data
# Second: tweets that contain the string "APT"

# In[4]:

l =[]
for tweet in FEtweets:
    if 'APT' in tweet.text:
        l.append(tweet.text)
print(l)

l2 = []
for tweet in FEItweets:
    if 'APT' in tweet.text:
        l2.append(tweet.text)
print(l2)


# Now that the tweets are starting to make sense however it doesnt seem like a lot of tweets. In fact counting the frequency of the string APT does not yield great results. 

# In[5]:

l_apt = []
for item in l:
    item = item.split(' ')
    for i in item:
        if 'APT' in i:
            print(i.strip())
            l_apt.append(i)
print(len(l_apt))

'''
Were this method to work, I would have then created a dictionary of all the different APTs and their common aliases and counted 
their frequency across different users
'''


# Well 16 results. Out of 200 tweets for 2 users, and no pagination available in the currently used lib, it would probably be best to go back to the aforementioned dataset. Furthermore using social media as a source for data for a huge company like FireEye will create unseen biases in your data. Some of these might not be correlated with increased activity, but rather increased publicity for a certain report, or an actively updated report.
# 
# If you would like to download the data for yourself you can find it here: apt.threattracking.com 

# In[6]:

import pandas as pd
import numpy as np


# First lets read all the CSVs of known APTs 

# In[7]:
#this data can be found at apt.threattracking.com and going to each country's tab
chn = pd.read_csv(r'China.csv')
rus = pd.read_csv(r'Russia.csv')
dprk = pd.read_csv(r'NK.csv')
irn = pd.read_csv(r'Iran.csv')
#r treats it like a raw text, no escape 


# A challenge here is not knowing the column names. This was easily done looking at the meta data of the set. 

# In[8]:

chn['TTP'] = chn['Unnamed: 16']
chn['TTP'].dropna()
#here we are converting the dataframe name, and dropping all na's so we only have content! 


# In[9]:

exploits = []

for item in chn['TTP'].dropna():
    item = item.split(',')
    #split by comma to isolate the exploit used
    print(item)
    exploits.append(item)
print(len(exploits))
#len of the list is the number of operations they conducted and have been reported on


# Now that we've seen the number of operations they've run and have been reported on, let's look at the diversity of their toolset

# In[10]:

exploit_dict = {}
for malware in chn['TTP'].dropna():
    malware = malware.split(',')
    #print(tool)
    for tool in malware:
        if tool in exploit_dict:
            exploit_dict[tool] = exploit_dict[tool] + 1
        else:
            exploit_dict[tool] = 1 
print(exploit_dict, exploit_dict[tool])
print(len(exploit_dict))
#diversity of toolset 


# There are 130 "unique" tools used 

# Next we will do the same for the countries. I will average the number of unique tools and the number of operations conducted
# to get a score of their "reach"

# In[11]:

rus['TTP'] = rus['Unnamed: 18']
exploits = []

for item in rus['TTP'].dropna():
    item = item.split(',')
    #split by comma to isolate the exploit used
    print(item)
    exploits.append(item)
print(len(exploits))
#len of the list is the number of operations they conducted and have been reported on

exploit_dict = {}
for malware in rus['TTP'].dropna():
    malware = malware.split(',')
    #print(tool)
    for tool in malware:
        if tool in exploit_dict:
            exploit_dict[tool] = exploit_dict[tool] + 1
        else:
            exploit_dict[tool] = 1 
print(exploit_dict, exploit_dict[tool])
print(len(exploit_dict))
#diversity of toolset 


# In[12]:

dprk['TTP'] = dprk['Unnamed: 16']
exploits = []

for item in dprk['TTP'].dropna():
    item = item.split(',')
    #split by comma to isolate the exploit used
    #print(item)
    exploits.append(item)
print(len(exploits))
#len of the list is the number of operations they conducted and have been reported on

exploit_dict = {}
for malware in dprk['TTP'].dropna():
    malware = malware.split(',')
    #print(tool)
    for tool in malware:
        if tool in exploit_dict:
            exploit_dict[tool] = exploit_dict[tool] + 1
        else:
            exploit_dict[tool] = 1 
print(exploit_dict, exploit_dict[tool])
print(len(exploit_dict))
#diversity of toolset 


# In[13]:

irn['TTP'] = irn['Unnamed: 9']
exploits = []

for item in irn['TTP'].dropna():
    item = item.split(',')
    #split by comma to isolate the exploit used
    #print(item)
    exploits.append(item)
print(len(exploits))
#len of the list is the number of operations they conducted and have been reported on

exploit_dict = {}
for malware in irn['TTP'].dropna():
    malware = malware.split(',')
    #print(tool)
    for tool in malware:
        if tool in exploit_dict:
            exploit_dict[tool] = exploit_dict[tool] + 1
        else:
            exploit_dict[tool] = 1 
print(exploit_dict, exploit_dict[tool])
print(len(exploit_dict))
#diversity of toolset 


# In[22]:

China =  (33 + 140) / 2
Russia =  (12 + 79) / 2
DPRK = (4 + 10) / 2
Iran = (10 + 33) / 2


# In[23]:

DPRK


# In[30]:

import gmaps
#use your API key here
gmaps.configure(api_key="XXXX")


# In[29]:

chn_gps = [(39.9, 116.4)]
rus_gps = [(55.8, 37.6)]
dprk_gps = [(39, 125.8)]
irn_gps = [(35.7, 51.4)]


# In[31]:

fig = gmaps.figure()
fig.add_layer(gmaps.heatmap_layer(list(chn_gps), point_radius=China))
fig.add_layer(gmaps.heatmap_layer(list(rus_gps), point_radius=Russia))
fig.add_layer(gmaps.heatmap_layer(list(dprk_gps), point_radius=DPRK))
fig.add_layer(gmaps.heatmap_layer(list(irn_gps), point_radius=Iran))
fig
# number of operations + number of unique exploits to get average score for radius 


# Here we can see that the most prolific actors to date are China and Russia. By visualizing the data in this way, we can see how the actions of Iran and North Korea (DPRK) are essentially dwarfed by cyber titans like China and Russia. Furthermore we can see the political biases inherent in cyber war as previously China was the US's greatest cyber adversary and first published APT (APT1). 
# 
# I predict that in the coming years, the raidus will shrink for China and increase for the other 3 simply due to the geopolitical climate. 
