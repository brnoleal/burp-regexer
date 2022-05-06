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
from javax.swing import ListSelectionModel
from javax.swing.table import DefaultTableModel
from javax.swing.table import AbstractTableModel

from java.util import ArrayList;
from java.awt import Color
from java.awt.event import MouseListener
from javax.swing.event import ChangeListener

import sys
import re
from threading import Lock
try:
    from exceptions_fix import FixBurpExceptions
except ImportError:
    pass


REGEX_DICT = {
    "URI Schemes": {
        "regex": "[a-zA-Z0-9-]*://[a-zA-Z0-9?=&\[\]:%_./-]+",
        "detail": "Extract all URI schemes.",
    },
    "Google API Key": {
        "regex": "AIza[0-9A-Za-z-_]{35}",
        "detail": "Get Google API Key."
    },
}

REGEX_TABLE = []


class BurpExtender(IBurpExtender, ITab, IHttpListener, IMessageEditorController, AbstractTableModel):

    def registerExtenderCallbacks(self, callbacks):
        print("Regexer v1.0")

        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._log = ArrayList()
        self._lock = Lock()

        self._jTextAreaLineMatched = JTextArea()
        self._jTextAreaLineMatched.setEditable(False)
        self._jTextAreaValueMatched = JTextArea()
        self._jTextAreaValueMatched.setEditable(False)
        self._jTextAreaAllResults = JTextArea()
        self._jTextAreaAllResults.setEditable(False)
        self._jTextAreaDetails = JTextArea()
        self._jTextAreaDetails.setEditable(False)
        
        self._requestViewer = self._callbacks.createMessageEditor(self, False)
        self._responseViewer = self._callbacks.createMessageEditor(self, False)        

        self.regexTableData = []
        self.regexTableColumns = ["#", "Rule Name", "Regex"]
        for key,value in REGEX_DICT.items():
            tmp = [v for v in value.values()]
            tmp.insert(0, key)
            tmp.insert(0, len(self.regexTableData))
            self.regexTableData.append(tmp)
        
        global REGEX_TABLE
        REGEX_TABLE = self.regexTableData
    
        self._callbacks.setExtensionName("Regexer")
        self._callbacks.addSuiteTab(self)
        self._callbacks.registerHttpListener(self)

        print("Processing proxy history, please wait...")
        self.processProxyHistory()
        print("Done!")
        
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
        self.processMessage(toolFlag, self._callbacks.saveBuffersToTempFiles(messageInfo))
        self._lock.release()   

    def processProxyHistory(self):
        proxyHistory = self._callbacks.getProxyHistory()
        for messageInfo in proxyHistory:
            self._lock.acquire()
            self.processMessage(4, self._callbacks.saveBuffersToTempFiles(messageInfo))
            self._lock.release()   

    def processMessage(self, toolFlag, messageInfo):
        if not messageInfo.getResponse():
            return 

        requestInfo = self._helpers.analyzeRequest(messageInfo.getRequest())
        requestHeader = requestInfo.getHeaders()
        requestBody = messageInfo.getRequest()[(requestInfo.getBodyOffset()):].tostring()

        responseInfo = self._helpers.analyzeResponse(messageInfo.getResponse())
        responseHeader = responseInfo.getHeaders()
        responseBody = messageInfo.getResponse()[(responseInfo.getBodyOffset()):].tostring()

        if requestHeader or responseHeader:
            headers = requestHeader + responseHeader
        else:
            headers = []

        if requestBody:
            requestLines = [line + '\n' for line in requestBody.split('\n')]
        else:
            requestLines = []

        if responseBody:
            responseLines = [line + '\n' for line in responseBody.split('\n')]
        else:
            responseLines = []
        
        self.processRegex(toolFlag, messageInfo, headers + requestLines + responseLines)

    def processRegex(self, toolFlag, messageInfo, lines):
        for regex in REGEX_TABLE:
            key = regex[1]
            regexPattern = regex[2]
            insertMessage = False

            if 'valueMatched' not in REGEX_DICT[key]:
                REGEX_DICT[key]['valueMatched'] = []
            if 'lineMatched' not in REGEX_DICT[key]:
                REGEX_DICT[key]['lineMatched'] = []                        
            if 'logEntry' not in REGEX_DICT[key]:
                REGEX_DICT[key]['logEntry'] = ArrayList()
            
            valueMatched = []
            lineMatched = []
            for line in lines:
                resultRegex = re.findall("{}".format(regexPattern), line)
                if resultRegex:
                    insertMessage = True
                    if line not in lineMatched:
                        lineMatched.append(line[:300])                    
                    for result in resultRegex:
                        if result not in valueMatched:
                            valueMatched.append(result)        
                    
            if insertMessage:
                logEntries = REGEX_DICT[key]['logEntry']
                row = len(logEntries)
                url = self._helpers.analyzeRequest(messageInfo).getUrl()
                method = self._helpers.analyzeRequest(messageInfo).getHeaders()[0].split(" ")[0]
                logEntry = LogEntry(
                    row, 
                    toolFlag, 
                    self._callbacks.saveBuffersToTempFiles(messageInfo), 
                    url, 
                    method,
                    lineMatched,
                    valueMatched)
                if logEntry not in logEntries:
                    REGEX_DICT[key]['logEntry'].add(logEntry)                          

            REGEX_DICT[key]['valueMatched'] += valueMatched
            REGEX_DICT[key]['lineMatched'] += lineMatched

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

    def getColumnClass(self, columnIndex):
        columnClasses = [Integer, String, String, String]
        return columnClasses[columnIndex]

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
        self.jScrollPaneAllResults = JScrollPane()
        self.jScrollPaneDetails = JScrollPane()
        self.jScrollPaneTableEntry = JScrollPane()
        self.jScrollPaneValueMatched = JScrollPane()
        self.jTabbedPane = JTabbedPane()
        self.jTabbedPane2 = JTabbedPane();
        self.jPanelRequest = JPanel()
        self.jPanelResponse = JPanel()

        self.jButtonAdd = JButton("Add", actionPerformed=self.handleJButtonAdd)
        self.jButtonRemove = JButton("Remove", actionPerformed=self.handleJButtonRemove)
        self.jButtonEdit = JButton("Edit", actionPerformed=self.handleJButtonEdit)
        self.jButtonClear = JButton("Clear", actionPerformed=self.handleJButtonClear)

        self.jTableEntry = EntryTable(self._extender)
        self.jScrollPaneTableEntry.setViewportView(self.jTableEntry)

        self.jTableRegex = RegexTable(self._extender, self.jTableEntry)
        self.jScrollPaneTableRegex.setViewportView(self.jTableRegex)

        self.jTabbedPane.addTab("Request", self._extender._requestViewer.getComponent())

        self.jTabbedPane.addTab("Response", self._extender._responseViewer.getComponent())

        self.jScrollPaneLineMatched.setViewportView(self._extender._jTextAreaLineMatched)
        self.jTabbedPane.addTab("Line Matched", self.jScrollPaneLineMatched)

        self.jScrollPaneValueMatched.setViewportView(self._extender._jTextAreaValueMatched)
        self.jTabbedPane.addTab("Value Matched", self.jScrollPaneValueMatched)

        self.jTabbedPane2.addTab("History", self.jSplitPane2)

        self.jScrollPaneAllResults.setViewportView(self._extender._jTextAreaAllResults)
        self.jTabbedPane2.addTab("All Results", self.jScrollPaneAllResults)

        self.jScrollPaneDetails.setViewportView(self._extender._jTextAreaDetails)
        self.jTabbedPane2.addTab("Details", self.jScrollPaneDetails)

        self.jTabbedPane2.addChangeListener(JTabbedPane2ChangeListener(self._extender, self.jTableRegex)) 

        self.jSplitPane2.setLeftComponent(self.jScrollPaneTableEntry)
        self.jSplitPane2.setRightComponent(self.jTabbedPane)

        self.jSplitPane1.setOrientation(JSplitPane.VERTICAL_SPLIT)
        self.jSplitPane1.setTopComponent(self.jScrollPaneTableRegex)
        self.jSplitPane1.setRightComponent(self.jTabbedPane2)

        layout = GroupLayout(self.jPanelMain)
        self.jPanelMain.setLayout(layout)
        layout.setHorizontalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(6, 6, 6)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING, False)
                    .addComponent(self.jButtonClear, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(self.jButtonEdit, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(self.jButtonAdd, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(self.jButtonRemove, GroupLayout.DEFAULT_SIZE, 86, Short.MAX_VALUE))
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(self.jSplitPane1))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addComponent(self.jButtonAdd, GroupLayout.PREFERRED_SIZE, 28, GroupLayout.PREFERRED_SIZE)
                .addGap(4, 4, 4)
                .addComponent(self.jButtonEdit, GroupLayout.PREFERRED_SIZE, 28, GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(self.jButtonRemove, GroupLayout.PREFERRED_SIZE, 28, GroupLayout.PREFERRED_SIZE)
                .addGap(56, 56, 56)
                .addComponent(self.jButtonClear, GroupLayout.PREFERRED_SIZE, 28, GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addContainerGap(GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
            .addComponent(self.jSplitPane1, GroupLayout.DEFAULT_SIZE, 603, Short.MAX_VALUE)
        );            

    def handleJButtonAdd(self, event):
        regexerGUIEdit = RegexerGUIEdit(self.jTableRegex, event)
        regexerGUIEdit.pack()
        regexerGUIEdit.show()

    def handleJButtonEdit(self, event):
        regexerGUIEdit = RegexerGUIEdit(self.jTableRegex, event)
        regexerGUIEdit.pack()
        regexerGUIEdit.show()

    def handleJButtonRemove(self, event):
        index = self.jTableRegex.getSelectedRow() 
        if(index != -1):
            self.jTableRegex.removeRow(index)
            JOptionPane.showMessageDialog(None, "Selected row successfully deleted!")

    def handleJButtonClear(self, event):
        index = self.jTableRegex.getSelectedRow() 
        if(index != -1):
            key = self.jTableRegex.getValueAt(index, 1)
            if 'logEntry' in REGEX_DICT[key]:
                REGEX_DICT[key]['logEntry'] = ArrayList()
                REGEX_DICT[key]['valueMatched'] = []

                self._extender._log = ArrayList()
                self._extender._requestViewer.setMessage("None", True)
                self._extender._responseViewer.setMessage("None", True)
                self._extender._jTextAreaLineMatched.setText("None")
                self._extender._jTextAreaValueMatched.setText("None")
                self.jTableEntry.getModel().fireTableDataChanged()

                JOptionPane.showMessageDialog(None, "Entries and results successfully cleared!")
                


class JTabbedPane2ChangeListener(ChangeListener):
    def __init__(self, extender, jTableRegex):
        self._extender = extender
        self.jTableRegex = jTableRegex

    def stateChanged(self, event):
        tab = event.getSource()
        index = tab.getSelectedIndex()
        title = tab.getTitleAt(index)
        
        if title == "All Results":
            try:
                key = self.jTableRegex.getValueAt(self.jTableRegex.getSelectedRow(), 1)
                if 'valueMatched' in REGEX_DICT[key] and  REGEX_DICT[key]['valueMatched'] != []:                
                    self._extender._jTextAreaAllResults.setText("\n".join(str(line).encode("utf-8").strip() for line in list(set(REGEX_DICT[key]['valueMatched']))))
                else: 
                    REGEX_DICT[key]['valueMatched'] = []
                    self._extender._jTextAreaAllResults.setText("No results found for '{}' regex.".format(key))
            except:
                self._extender._jTextAreaAllResults.setText("Select one rule from regex table to show it's results.")
        
        if title == "Details":
            try:
                key = self.jTableRegex.getValueAt(self.jTableRegex.getSelectedRow(), 1)
                regex = self.jTableRegex.getValueAt(self.jTableRegex.getSelectedRow(), 2)            
                length = len(REGEX_DICT[key]['valueMatched'])
                uniq = len(list(set(REGEX_DICT[key]['valueMatched'])))
                details = '''
                {} results found for this regex.\n
                {} uniq results show in 'All Results' tab.\n
                \nRule name: 
                {}
                \nRegex: 
                {}
                '''.format(length, uniq, key, regex)
                self._extender._jTextAreaDetails.setText(details)
            except:
                self._extender._jTextAreaDetails.setText("Select one rule from regex table to show it's results.")


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

        self.jTextFieldkey = JTextField()
        self.jTextFieldRegex = JTextField()

        if event.source.text == "Add":
            self.setTitle("Add Regex Rule")
        elif event.source.text == "Edit":
            self.setTitle("Edit Regex Rule")
            self.jTextFieldkey.setText(self.jTableRegex.getValueAt(self.jTableRegex.getSelectedRow(), 1))
            self.jTextFieldRegex.setText(self.jTableRegex.getValueAt(self.jTableRegex.getSelectedRow(), 2))
        
        self.jButtonOK = JButton("OK", actionPerformed=self.addEditRegex)
        self.jButtonCancel = JButton("Cancel", actionPerformed=self.closeRegexerGUIEdit)

        self.jTextFieldkey.setToolTipText("")
        self.jTextFieldkey.setBorder(BorderFactory.createLineBorder(Color.lightGray));
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
                                .addComponent(self.jTextFieldkey)
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
                    .addComponent(self.jTextFieldkey, GroupLayout.PREFERRED_SIZE, 24, GroupLayout.PREFERRED_SIZE))
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
        key =  self.jTextFieldkey.getText()
        regex = self.jTextFieldRegex.getText()
        if self._event.source.text == "Add":
            try:
                lastIndex = self.jTableRegex.getValueAt(self.jTableRegex.getRowCount()-1, 0)
            except:
                lastIndex = 0
            self.jTableRegex.addRow([lastIndex + 1, key, regex])            
            REGEX_TABLE = self.jTableRegex.getModel().getDataVector()
            self.updateRegexDict(key, regex)
            self.dispose()
        elif self._event.source.text == "Edit":
            rowIndex = self.jTableRegex.getSelectedRow()
            self.jTableRegex.setValueAt(key, rowIndex, 1)
            self.jTableRegex.setValueAt(regex, rowIndex, 2)
            REGEX_TABLE = self.jTableRegex.getModel().getDataVector()
            self.updateRegexDict(key, regex)
            self.dispose()

    def updateRegexDict(self, key, regex):
        if key not in REGEX_DICT:
            REGEX_DICT[key] = {}
        else: 
            REGEX_DICT[key]['regex'] = regex

    def closeRegexerGUIEdit(self, event):
        self.dispose()


class RegexTable(JTable):

    def __init__(self, extender, jTableEntry):
        self._extender = extender
        self._jTableEntry = jTableEntry
        model = RegexTableModel(self._extender.regexTableData, self._extender.regexTableColumns)

        self.setModel(model)
        self.setAutoCreateRowSorter(True)
        self.getTableHeader().setReorderingAllowed(False)
        self.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS)
        self.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self.addMouseListener(RegexTableMouseListener(self._extender, self._jTableEntry))

    def addRow(self, data):
        self.getModel().addRow(data)

    def removeRow(self, row):
        self.getModel().removeRow(row)

    def setValueAt(self, value, row, column):
        self.getModel().setValueAt(value, row, column)


class RegexTableModel(DefaultTableModel):

    def __init__(self, data, columns):
        DefaultTableModel.__init__(self, data, columns)

    def isCellEditable(self, row, column):
        canEdit = [False, False, False]
        return canEdit[column]

    def getColumnClass(self, column):
        columnClasses = [Integer, String, String]
        return columnClasses[column]


class RegexTableMouseListener(MouseListener):
    
    def __init__(self, extender, jTableEntry):
        self._extender = extender
        self._jTableEntry = jTableEntry

    def getClickedRow(self, event):
        regexTable = event.getSource()
        return regexTable.getModel().getDataVector().elementAt(regexTable.convertRowIndexToModel(regexTable.getSelectedRow()))

    def getClickedIndex(self, event):
        regexTable = event.getSource()
        row = regexTable.convertRowIndexToModel(regexTable.getSelectedRow())
        return regexTable.getValueAt(row, 0)

    def mouseClicked(self, event):
        key = self.getClickedRow(event)[1]
        regex = self.getClickedRow(event)[2]  
        
        if 'logEntry' in REGEX_DICT[key]:
            self._extender._log = REGEX_DICT[key]['logEntry']
            self._jTableEntry.getModel().fireTableDataChanged()
            try:
                logEntry = self._extender._log.get(0)
                self._extender._requestViewer.setMessage(logEntry._requestResponse.getRequest(), True)
                self._extender._responseViewer.setMessage(logEntry._requestResponse.getResponse(), True)
                self._extender._jTextAreaLineMatched.setText("\n".join(str(line).encode("utf-8").strip() for line in logEntry._lineMatched))
                self._extender._jTextAreaValueMatched.setText("\n".join(str(value).encode("utf-8").strip() for value in logEntry._valueMatched))
                self._extender._currentlyDisplayedItem = logEntry._requestResponse       
            except:
                self._extender._requestViewer.setMessage("None", True)
                self._extender._responseViewer.setMessage("None", True)
                self._extender._jTextAreaLineMatched.setText("None")
                self._extender._jTextAreaValueMatched.setText("None")
        else:
            REGEX_DICT[key]['logEntry'] = ArrayList()

        try:
            if 'valueMatched' in REGEX_DICT[key] and  REGEX_DICT[key]['valueMatched'] != []:                
                self._extender._jTextAreaAllResults.setText(
                    "\n".join(str(line).encode("utf-8").strip() for line in list(set(REGEX_DICT[key]['valueMatched'])))
                )
            else: 
                REGEX_DICT[key]['valueMatched'] = []
                self._extender._jTextAreaAllResults.setText("No results found for '{}' regex.".format(key))
        except:
            self._extender._jTextAreaAllResults.setText("Select one rule from regex table to show it's results.")
           
        try:
            length = len(REGEX_DICT[key]['valueMatched'])
            uniq = len(list(set(REGEX_DICT[key]['valueMatched'])))
            details = '''
                {} results found for this regex.\n
                {} uniq results show in 'All Results' tab.\n
                \nRule name: 
                {}
                \nRegex: 
                {}
                '''.format(length, uniq, key, regex)
            self._extender._jTextAreaDetails.setText(details)
        except:
            self._extender._jTextAreaDetails.setText("Select one rule from regex table to show it's results.")            

    def mousePressed(self, event):
        pass

    def mouseReleased(self, event):
        pass

    def mouseEntered(self, event):
        pass

    def mouseExited(self, event):
        pass


class EntryTable(JTable):

    def __init__(self, extender):
        self._extender = extender
        self.setModel(extender)
        self.setAutoCreateRowSorter(True)
        self.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        self.getTableHeader().setReorderingAllowed(False)

    def changeSelection(self, row, col, toggle, extend):
        print(row)
        index = self.getValueAt(row, 0)
        print(index)
        logEntry = self._extender._log.get(index)
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


class RegexEntry:
    def __init__(self, index, key, regex, logEntry):
        self._index = index
        self._key = key
        self._regex = regex
        self._logEntry = logEntry


# support for burp-exceptions
try:
    FixBurpExceptions()
except:
    pass