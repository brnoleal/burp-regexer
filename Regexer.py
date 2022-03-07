from burp import IBurpExtender
from burp import IHttpListener
from burp import IMessageEditorController
from burp import ITab
from java.awt import BorderLayout
from java.util import ArrayList
from javax.swing import Box
from javax.swing import JButton
from javax.swing import JLabel
from javax.swing import JOptionPane
from javax.swing import JPanel
from javax.swing import JScrollPane
from javax.swing import JSplitPane
from javax.swing import JTabbedPane
from javax.swing import JTable
from javax.swing import JTextField
from javax.swing.table import AbstractTableModel;
from threading import Lock


class BurpExtender(IBurpExtender, ITab, IHttpListener, IMessageEditorController, AbstractTableModel):

    # 
    # implement IBurpExtender
    #

    def registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks

        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()

        # define our extension name
        callbacks.setExtensionName("Regexer")

        # create the log, regex and a lock on which to synchronize when adding log entries
        self._log = ArrayList()
        self._regex = ArrayList()
        self._lock = Lock()

        # history tab split pane
        splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)

        # table of log entries
        logTable = Table(self)
        scrollPane =  JScrollPane(logTable)
        splitpane.setLeftComponent(scrollPane)

        # tabs with request/response viewers
        tabs = JTabbedPane()
        self._requestViewer = callbacks.createMessageEditor(self, False)
        self._responseViewer = callbacks.createMessageEditor(self, False)
        tabs.addTab("Request", self._requestViewer.getComponent())
        tabs.addTab("Response", self._responseViewer.getComponent())
        splitpane.setRightComponent(tabs)
        
        # regex tab panel
        panel = JPanel(BorderLayout())
        
        box = Box.createHorizontalBox() 
        box.add(JLabel("Regular Expression: "))
        box.add(JTextField(100, actionPerformed=self.updateRegex))
        box.add(JButton("Update", actionPerformed=self.updateRegex))
        box.add(JButton("?", actionPerformed=self.help))
        
        panel.add(box, BorderLayout.NORTH)

        box = Box.createHorizontalBox() 
        self._regex.add([1, "Issue1", "Severity1"])
        self._regex.add([2, "Issue2", "Severity2"])
        self._regex.add([3, "Issue3", "Severity3"])
        self._tableHeadings = ["#", "Rule Name", "Regular Expression"]
        self._regexTable = JTable(self._regex, self._tableHeadings)
        regexScrollPane = JScrollPane(self._regexTable)
        
        panel.add(regexScrollPane, BorderLayout.CENTER)

        # main tabs 
        self._tabs = JTabbedPane()
        self._tabs.addTab("History", splitpane)
        self._tabs.addTab("Regex", panel)

        # customize our UI components
        callbacks.customizeUiComponent(self._tabs)
        callbacks.customizeUiComponent(splitpane)
        callbacks.customizeUiComponent(logTable)
        callbacks.customizeUiComponent(scrollPane)
        callbacks.customizeUiComponent(tabs) 

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

    #
    # implement ITextEditor
    #


    #
    # implement IHttpListener
    #

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # only process requests
        if messageIsRequest:
            return

        # create a new log entry with the message details
        self._lock.acquire()
        row = self._log.size()
        self._log.add(LogEntry(toolFlag, self._callbacks.saveBuffersToTempFiles(messageInfo), self._helpers.analyzeRequest(messageInfo).getUrl()))
        self.fireTableRowsInserted(row, row)
        self._lock.release()

    #
    # extend AbstractTableModel
    #

    def getRowCount(self):
        try:
            return self._log.size()
        except:
            return 0

    def getColumnCount(self):
        return 2

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "Tool"
        if columnIndex == 1:
            return "URL"
        return ""

    def getValueAt(self, rowIndex, columnIndex):
        logEntry = self._log.get(rowIndex)
        if columnIndex == 0:
            return self._callbacks.getToolName(logEntry._tool)
        if columnIndex == 1:
            return logEntry._url.toString()
        return ""

    #
    # auxiliary methods
    #

    def updateRegex(self, event):
        print("UPDATE REGEX")
        self._regex.add([4, "Issue4", "Severity4"])
        print(self._regex)

    def help(self, event):
        JOptionPane.showMessageDialog(None, "All matching subgroups will also be extracted.")

    # 
    # implement IMessageEditorController
    # this allows our request/response viewers to obtain details about the messages being displayed 
    #

    def getHttpService(self):
        return self._currentlyDisplayedItem.getHttpService()

    def getRequest(self):
        return self._currentlyDisplayedItem.getRequest()

    def getResponse(self):
        return self._currentlyDisplayedItem.getResponse()

    
#
# extend JTable to handle cell selection
#

class Table(JTable):
    def __init__(self, extender):
        self._extender = extender
        self.setModel(extender)

    def changeSelection(self, row, col, toggle, extend):
        # show the log entry for the selected row
        logEntry = self._extender._log.get(row)
        self._extender._requestViewer.setMessage(logEntry._requestResponse.getRequest(), True)
        self._extender._responseViewer.setMessage(logEntry._requestResponse.getResponse(), True)
        self._extender._currentlyDisplayedItem = logEntry._requestResponse

        JTable.changeSelection(self, row, col, toggle, extend)


#
# class to hold details of each log entry
#

class LogEntry:
    def __init__(self, tool, requestResponse, url):
        self._tool = tool
        self._requestResponse = requestResponse
        self._url = url