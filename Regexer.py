from burp import IBurpExtender
from burp import ITab


class BurpExtender(IBurpExtender, ITab):

    #
    #  implement IBurpExtender
    #

    def registerExtenderCallbacks(self, callbacks):

        return

    #
    # implement ITab
    #

    def getTabCaption(self):
        return "Regexer"
