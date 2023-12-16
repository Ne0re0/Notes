# Bot Discord

## Requirements
- discord.py library 
```bash
python3 -m pip install -U discord.py
```
- discord account
- discord server


## Create the application
Go to https://discord.com/developers/applications and click `new Application`

## Create the bot
Go to bot and click new
- Enable all gateway intents

## Join the bot to your server
Click OAuth2 and then URL generator, change permissions to be like : 
- Scopes : bot
- General permission : Administrator 

Copy the given url and paste it in the url bar and add the bot to the desired server


## PoC

```py
#!/usr/bin/python3

import discord 
from discord.ext import commands 

# Prefiw is what you type before the command
bot = commands.Bot(command_prefix="!", description = "Le guide du routard",intents = discord.Intents.all())

# Starts when the bot is ready
@bot.event 
async def on_ready() : 
    print("Ready !")

bot.run('token_here')
```

## Fonctions
```py
# Define the command !coucou which write coucou in a channel
@bot.command()
async def coucou(context) : 
    await context.send("coucou")
```

```py
# Define the command !say which write parameters
# Note that parameters are split from spaces
@bot.command()
async def say(context,text) : 
    await context.send("text")

@bot.command()
async def say(context,*text) : 
    await context.send("text")
```

## CheatSheet 
```py
server = context.guild
description = server.description		# string
text_channels = server.text_channels   	# list
voice_channels = server.voice_channels 	# list
account_nb = server.member_count
```