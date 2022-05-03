from burp import IBurpExtender
from burp import IHttpListener
from burp import IMessageEditorController
from burp import ITab

from java.lang import Integer
from java.lang import Object
from java.lang import Short
from java.lang import String

from javax.swing import BorderFactory
from javax.swing import GroupLayout
from javax.swing import LayoutStyle
from javax.swing import WindowConstants
from javax.swing import UnsupportedLookAndFeelException

from javax.swing import JButton
from javax.swing import JFrame
from javax.swing import JLabel
from javax.swing import JOptionPane
from javax.swing import JPanel
from javax.swing import JScrollPane
from javax.swing import JSplitPane
from javax.swing import JTable
from javax.swing import JTabbedPane
from javax.swing import JTextArea
from javax.swing import JTextField
from javax.swing.table import DefaultTableModel
from javax.swing.table import AbstractTableModel
from javax.swing.table import TableRowSorter

from java.util import ArrayList;
from java.awt import Color
from java.awt.event import MouseListener

import sys
import re
from threading import Lock
try:
    from exceptions_fix import FixBurpExceptions
except ImportError:
    pass


REGEX_DICT = {
    "URI Schemes": {
        "regex": "[a-zA-Z0-9-]*://[a-zA-Z0-9_./-]+",
        "detail": "Extract all URI schemes."
    },
    "Google API Key": {
        "regex": "AIza[0-9A-Za-z-_]{35}",
        "detail": "Get Google API Key."
    },
}

REGEX_TABLE = []


class BurpExtender(IBurpExtender, ITab, IHttpListener, IMessageEditorController, AbstractTableModel):

    def registerExtenderCallbacks(self, callbacks):

        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._log = ArrayList()
        self._lock = Lock()

        self._jTextAreaLineMatched = JTextArea()
        self._jTextAreaLineMatched.setEditable(False);
        self._jTextAreaValueMatched = JTextArea()
        self._jTextAreaValueMatched.setEditable(False);
        
        self._requestViewer = self._callbacks.createMessageEditor(self, False)
        self._responseViewer = self._callbacks.createMessageEditor(self, False)        

        # self.regexTableData = [
        #     [1, "URI Schemes", "([a-zA-Z0-9-]*://[a-zA-Z0-9_./-]+)"],
        #     [2, "2nd rule", "url="],
        #     [3, "3rd rule", "<a link="],
        #     [4, "4rd rule", "Sec"]
        # ]
  
        global REGEX_TABLE
        self.regexTableData = []
        for key,value in REGEX_DICT.items():
            tmp = [v for v in value.values()]
            tmp.insert(0, key)
            tmp.insert(0, len(self.regexTableData))
            print(tmp)
            self.regexTableData.append(tmp)
        REGEX_TABLE = self.regexTableData

        self.regexTableColumns = ["#", "Rule Name", "Regex"]
        self.entryTableColumns = ["Tool", "URI"]        

        try:
            sys.stdout = callbacks.getStdout()
        except:
            pass

        callbacks.setExtensionName("Regexer")
        callbacks.addSuiteTab(self)
        callbacks.registerHttpListener(self)
        return

    def getTabCaption(self):
        return "Regexer"

    def getUiComponent(self):
        regexerGui = RegexerGUI(self)
        return regexerGui.jPanelMain

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return

        self._lock.acquire()
        row = self._log.size()
        url = self._helpers.analyzeRequest(messageInfo).getUrl()
        method = self._helpers.analyzeRequest(messageInfo).getHeaders()[0].split(" ")[0]
        lineMatched, valueMatched = self.processMessage(self._callbacks.saveBuffersToTempFiles(messageInfo))
        if lineMatched or valueMatched:
            self._log.add(LogEntry(row, 
                                    toolFlag, 
                                    self._callbacks.saveBuffersToTempFiles(messageInfo), 
                                    url, 
                                    method,
                                    lineMatched,
                                    valueMatched))
            self.fireTableRowsInserted(row, row)
        self._lock.release()   

    def processMessage(self, messageInfo):
        lineMatched = []
        valueMatched = []

        requestInfo = self._helpers.analyzeRequest(messageInfo.getRequest())
        requestHeader = requestInfo.getHeaders()
        requestBody = messageInfo.getRequest()[(requestInfo.getBodyOffset()):].tostring()

        responseInfo = self._helpers.analyzeResponse(messageInfo.getResponse())
        responseHeader = responseInfo.getHeaders()
        responseBody = messageInfo.getResponse()[(responseInfo.getBodyOffset()):].tostring()

        if requestHeader or responseHeader:
            headers = requestHeader + responseHeader
            self.processRegex(headers, lineMatched, valueMatched)

        if requestBody:
            requestLines = [line + '\n' for line in requestBody.split('\n')]
            self.processRegex(requestLines, lineMatched, valueMatched)

        if responseBody:
            responseLines = [line + '\n' for line in responseBody.split('\n')]
            self.processRegex(responseLines, lineMatched, valueMatched)

        return lineMatched, valueMatched

    def processRegex(self, lines, lineMatched, valueMatched):
        global REGEX_TABLE
        for line in lines:
            for regex in REGEX_TABLE:
                resultRegex = re.findall("{}".format(regex[2]), line)
                if resultRegex:
                    for result in resultRegex:
                        if result not in valueMatched:
                            valueMatched.append(result)
                    if line not in lineMatched:
                        lineMatched.append(line)

    def getRowCount(self):
        try:
            return self._log.size()
        except:
            return 0

    def getColumnCount(self):
        return 4

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "#"
        if columnIndex == 1:
            return "Tool"
        if columnIndex == 2:
            return "Method"
        if columnIndex == 3:
            return "URI"
        return ""

    def getValueAt(self, rowIndex, columnIndex):
        logEntry = self._log.get(rowIndex)
        if columnIndex == 0:
            return logEntry._index
        if columnIndex == 1:
            return self._callbacks.getToolName(logEntry._tool)
        if columnIndex == 2:
            return logEntry._method
        if columnIndex == 3:
            return logEntry._url.toString()
        return ""

    def getHttpService(self):
        return self._currentlyDisplayedItem.getHttpService()

    def getRequest(self):
        return self._currentlyDisplayedItem.getRequest()

    def getResponse(self):
        return self._currentlyDisplayedItem.getResponse()


class RegexerGUI(JFrame):

    def __init__(self, extender):
        self._extender = extender
        self.jPanelMain = JPanel()

        self.jSplitPane1 = JSplitPane()
        self.jSplitPane2 = JSplitPane()
        self.jScrollPaneTableRegex = JScrollPane()
        self.jScrollPaneLineMatched = JScrollPane()
        self.jScrollPaneTableEntry = JScrollPane()
        self.jScrollPaneValueMatched = JScrollPane()
        self.jTabbedPane = JTabbedPane()
        self.jPanelRequest = JPanel()
        self.jPanelResponse = JPanel()

        self.jButtonAdd = JButton("Add", actionPerformed=self.handleJButtonAdd)
        self.jButtonRemove = JButton("Remove", actionPerformed=self.handleJButtonRemove)
        self.jButtonEdit = JButton("Edit", actionPerformed=self.handleJButtonEdit)
        self.jButtonCopy = JButton("Copy")
        self.jButtonClear = JButton("Clear")

        self.jTableRegex = RegexTable(self._extender)
        self.jScrollPaneTableRegex.setViewportView(self.jTableRegex)

        self.jTableEntry = EntryTable(self._extender)
        self.jScrollPaneTableEntry.setViewportView(self.jTableEntry)

        self.jSplitPane2.setLeftComponent(self.jScrollPaneTableEntry)
        self.jSplitPane2.setRightComponent(self.jTabbedPane)

        self.jSplitPane1.setTopComponent(self.jScrollPaneTableRegex)
        self.jSplitPane1.setRightComponent(self.jSplitPane2)
        self.jSplitPane1.setOrientation(JSplitPane.VERTICAL_SPLIT)

        self.jTabbedPane.addTab("Request", self._extender._requestViewer.getComponent())
        self.jTabbedPane.addTab("Response", self._extender._responseViewer.getComponent())

        self.jScrollPaneLineMatched.setViewportView(self._extender._jTextAreaLineMatched)
        self.jTabbedPane.addTab("Line Matched", self.jScrollPaneLineMatched)

        self.jScrollPaneValueMatched.setViewportView(self._extender._jTextAreaValueMatched)
        self.jTabbedPane.addTab("Value Matched", self.jScrollPaneValueMatched)

        layout = GroupLayout(self.jPanelMain)
        self.jPanelMain.setLayout(layout)
        layout.setHorizontalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(6, 6, 6)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING, False)
                    .addComponent(self.jButtonCopy, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(self.jButtonEdit, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(self.jButtonAdd, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(self.jButtonRemove, GroupLayout.DEFAULT_SIZE, 86, Short.MAX_VALUE)
                    .addComponent(self.jButtonClear, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(self.jSplitPane1))
        )
        layout.setVerticalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addComponent(self.jButtonAdd, GroupLayout.PREFERRED_SIZE, 28, GroupLayout.PREFERRED_SIZE)
                .addGap(4, 4, 4)
                .addComponent(self.jButtonEdit, GroupLayout.PREFERRED_SIZE, 28, GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(self.jButtonRemove, GroupLayout.PREFERRED_SIZE, 28, GroupLayout.PREFERRED_SIZE)
                .addGap(56, 56, 56)
                .addComponent(self.jButtonCopy, GroupLayout.PREFERRED_SIZE, 28, GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(self.jButtonClear, GroupLayout.PREFERRED_SIZE, 28, GroupLayout.PREFERRED_SIZE)
                .addContainerGap(GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
            .addComponent(self.jSplitPane1, GroupLayout.DEFAULT_SIZE, 525, Short.MAX_VALUE)
        )            

    def handleJButtonAdd(self, event):
        regexerGUIEdit = RegexerGUIEdit(self.jTableRegex, event)
        regexerGUIEdit.pack()
        regexerGUIEdit.show()

    def handleJButtonEdit(self, event):
        regexerGUIEdit = RegexerGUIEdit(self.jTableRegex, event)
        regexerGUIEdit.pack()
        regexerGUIEdit.show()

    def handleJButtonRemove(self, event):
        if(self.jTableRegex.getSelectedRow() != -1):
            self.jTableRegex.removeRow(self.jTableRegex.getSelectedRow())
            JOptionPane.showMessageDialog(None, "Selected row deleted successfully")


class RegexerGUIEdit(JFrame):

    def __init__(self, jTableRegex, event):
        self.jTableRegex = jTableRegex
        self._event = event
        
        self.jLabel1 = JLabel()
        self.jLabel1.setText("Specify the details of the regex rule.")
        
        self.jLabel2 = JLabel()
        self.jLabel2.setText("Rule Name:")
        
        self.jLabel3 = JLabel()
        self.jLabel3.setText("Regex:")

        self.jTextFieldRuleName = JTextField()
        self.jTextFieldRegex = JTextField()

        if event.source.text == "Add":
            self.setTitle("Add Regex Rule")
        elif event.source.text == "Edit":
            self.setTitle("Edit Regex Rule")
            self.jTextFieldRuleName.setText(self.jTableRegex.getValueAt(self.jTableRegex.getSelectedRow(), 1))
            self.jTextFieldRegex.setText(self.jTableRegex.getValueAt(self.jTableRegex.getSelectedRow(), 2))
        
        self.jButtonOK = JButton("OK", actionPerformed=self.addEditRegex)
        self.jButtonCancel = JButton("Cancel", actionPerformed=self.closeRegexerGUIEdit)

        self.jTextFieldRuleName.setToolTipText("")
        self.jTextFieldRuleName.setBorder(BorderFactory.createLineBorder(Color.lightGray));
        self.jTextFieldRegex.setToolTipText("")
        self.jTextFieldRegex.setBorder(BorderFactory.createLineBorder(Color.lightGray));
        
        layout = GroupLayout(self.getContentPane())
        self.getContentPane().setLayout(layout)
        layout.setHorizontalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(20, 20, 20)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                    .addComponent(self.jLabel1)
                    .addGroup(layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                        .addGroup(layout.createSequentialGroup()
                            .addComponent(self.jButtonOK, GroupLayout.PREFERRED_SIZE, 70, GroupLayout.PREFERRED_SIZE)
                            .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                            .addComponent(self.jButtonCancel, GroupLayout.PREFERRED_SIZE, 70, GroupLayout.PREFERRED_SIZE))
                        .addGroup(layout.createSequentialGroup()
                            .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                .addComponent(self.jLabel2)
                                .addComponent(self.jLabel3))
                            .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                            .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING, False)
                                .addComponent(self.jTextFieldRuleName)
                                .addComponent(self.jTextFieldRegex, GroupLayout.DEFAULT_SIZE, 382, Short.MAX_VALUE)))))
                .addContainerGap(20, Short.MAX_VALUE))
        )
        layout.setVerticalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(20, 20, 20)
                .addComponent(self.jLabel1)
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                    .addComponent(self.jLabel2)
                    .addComponent(self.jTextFieldRuleName, GroupLayout.PREFERRED_SIZE, 24, GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self.jLabel3)
                    .addComponent(self.jTextFieldRegex, GroupLayout.PREFERRED_SIZE, 24, GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                    .addComponent(self.jButtonCancel, GroupLayout.PREFERRED_SIZE, 27, GroupLayout.PREFERRED_SIZE)
                    .addComponent(self.jButtonOK, GroupLayout.PREFERRED_SIZE, 27, GroupLayout.PREFERRED_SIZE))
                .addContainerGap(GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        )

    def addEditRegex(self, event):
        global REGEX_TABLE
        if self._event.source.text == "Add":
            lastIndex = self.jTableRegex.getValueAt(self.jTableRegex.getRowCount()-1, 0)
            self.jTableRegex.addRow([lastIndex + 1, self.jTextFieldRuleName.getText(), self.jTextFieldRegex.getText()])            
            REGEX_TABLE = self.jTableRegex.getModel().getDataVector()
            self.dispose()
        elif self._event.source.text == "Edit":
            rowIndex = self.jTableRegex.getSelectedRow()
            self.jTableRegex.setValueAt(self.jTextFieldRuleName.getText(), rowIndex, 1) # Rule Name column
            self.jTableRegex.setValueAt(self.jTextFieldRegex.getText(), rowIndex, 2) # Regex Rule column
            REGEX_TABLE = self.jTableRegex.getModel().getDataVector()
            print(REGEX_TABLE)
            self.dispose()

    def closeRegexerGUIEdit(self, event):
        self.dispose()


class RegexTableModel(DefaultTableModel):

    def __init__(self, data, columns):
        DefaultTableModel.__init__(self, data, columns)

    def isCellEditable(self, row, column):
        canEdit = [False, False, False]
        return canEdit[column]

    def getColumnClass(self, column):
        columnClasses = [Integer, String, String]
        return columnClasses[column]


class RegexTable(JTable):

    def __init__(self, extender):
        model = RegexTableModel(extender.regexTableData, extender.regexTableColumns)
        self.setModel(model)
        sorter = TableRowSorter(model)
        self.setRowSorter(sorter)
        # self.setAutoCreateRowSorter(True)
        self.getTableHeader().setReorderingAllowed(False)

    def addRow(self, data):
        self.getModel().addRow(data)

    def removeRow(self, row):
        self.getModel().removeRow(row)

    def setValueAt(self, value, row, column):
        self.getModel().setValueAt(value, row, column)


class EntryTable(JTable):

    def __init__(self, extender):
        self._extender = extender
        self.setModel(extender)
        sorter = TableRowSorter(extender)
        self.setRowSorter(sorter)
        # self.setAutoCreateRowSorter(True)
        self.getTableHeader().setReorderingAllowed(False)

    def changeSelection(self, row, col, toggle, extend):
        logEntry = self._extender._log.get(row)
        self._extender._requestViewer.setMessage(logEntry._requestResponse.getRequest(), True)
        self._extender._responseViewer.setMessage(logEntry._requestResponse.getResponse(), True)
        self._extender._jTextAreaLineMatched.setText("\n".join(str(line).encode("utf-8").strip() for line in logEntry._lineMatched))
        self._extender._jTextAreaValueMatched.setText("\n".join(str(value).encode("utf-8").strip() for value in logEntry._valueMatched))
        self._extender._currentlyDisplayedItem = logEntry._requestResponse
        JTable.changeSelection(self, row, col, toggle, extend)


class LogEntry:
    def __init__(self, index, tool, requestResponse, url, method, lineMatched, valueMatched):
        self._index = index
        self._tool = tool
        self._requestResponse = requestResponse
        self._url = url
        self._method = method
        self._lineMatched = lineMatched
        self._valueMatched = valueMatched


# support for burp-exceptions
try:
    FixBurpExceptions()
except:
    pass