from burp import IBurpExtender
from burp import ITab
from burp import IHttpListener
from javax.swing import JPanel;
from javax.swing import JTabbedPane;


class BurpExtender(IBurpExtender, ITab, IHttpListener):

    #
    #  implement IBurpExtender
    #

    def registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks

        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()

        # tabs 
        self._tabs = JTabbedPane()
        panel1 = JPanel()
        panel2 = JPanel()
        self._tabs.addTab("History", panel1)
        self._tabs.addTab("Config", panel2)

        # customize our UI components
        callbacks.customizeUiComponent(self._tabs)

        # add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)

        # register ourselves as an HTTP listener
        callbacks.registerHttpListener(self)

        return

    #
    # implement ITab
    #

    def getTabCaption(self):
        return "Regexer"

    def getUiComponent(self):
        return self._tabs