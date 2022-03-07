from burp import IBurpExtender
from burp import ITab

from java.lang import Integer
from java.lang import Object
from java.lang import Short
from java.lang import String

from javax.swing import JFrame
from javax.swing import JPanel
from javax.swing import JScrollPane
from javax.swing import JTable
from javax.swing import JButton
from javax.swing import WindowConstants
from javax.swing import GroupLayout
from javax.swing import LayoutStyle
from javax.swing import UnsupportedLookAndFeelException
from javax.swing.table import DefaultTableModel

from java.awt.event import MouseListener

import sys
try:
    from exceptions_fix import FixBurpExceptions
except ImportError:
    pass


class BurpExtender(IBurpExtender, ITab):

    def registerExtenderCallbacks(self, callbacks):

        # support for burp-exceptions
        try:
            sys.stdout = callbacks.getStdout()
        except:
            pass

        # set our extension name
        callbacks.setExtensionName("RegexerGUI")

        # add the tab to Burp's UI
        callbacks.addSuiteTab(self)

    #
    # implement ITab
    # 

    def getTabCaption(self):
        return "RegexerGUI"

    def getUiComponent(self):
        regexerGui = RegexerGUI()
        # regexerGui.pack()
        # regexerGui.show()
        return regexerGui.panel


class RegexerGUI(JFrame):

    def __init__(self):

        # define variables
        self.jScrollPane1 = JScrollPane()
        self.jTableRegex = JTable()
        self.jButtonAdd = JButton()
        self.jButtonRemove = JButton()
        self.jButtonEdit = JButton()

        # setting up the table
        tableData = [
            [1, "1st rule", "://"],
            [2, "2nd rule", "url="],
            [3, "3rd rule", "<a link="]
        ]
        tableColumns = ["#", "Rule Name", "Regex Rule"]

        # set the table model
        self.jTableRegex = RegexTable(tableData, tableColumns)

        # wrap the table in a scrollpane
        self.jScrollPane1.setViewportView(self.jTableRegex)

        # define button names
        self.jButtonAdd.setText("Add")
        self.jButtonRemove.setText("Remove")
        self.jButtonEdit.setText("Edit")

        # layout of GUI
        self.panel = JPanel()
        layout = GroupLayout(self.panel)
        self.panel.setLayout(layout)
        layout.setAutoCreateGaps(True)
        layout.setHorizontalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.TRAILING, False)
                    .addComponent(self.jButtonEdit, GroupLayout.Alignment.LEADING, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(self.jButtonAdd, GroupLayout.Alignment.LEADING, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(self.jButtonRemove, GroupLayout.DEFAULT_SIZE, 86, Short.MAX_VALUE))
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(self.jScrollPane1, GroupLayout.DEFAULT_SIZE, 795, Short.MAX_VALUE))
        )
        layout.setVerticalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addComponent(self.jScrollPane1, GroupLayout.PREFERRED_SIZE, 0, Short.MAX_VALUE)
            .addGroup(layout.createSequentialGroup()
                .addGap(23, 23, 23)
                .addComponent(self.jButtonAdd, GroupLayout.PREFERRED_SIZE, 28, GroupLayout.PREFERRED_SIZE)
                .addGap(4, 4, 4)
                .addComponent(self.jButtonEdit, GroupLayout.PREFERRED_SIZE, 28, GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(self.jButtonRemove, GroupLayout.PREFERRED_SIZE, 28, GroupLayout.PREFERRED_SIZE)
                .addContainerGap(183, Short.MAX_VALUE))
        )                       


class RegexTableModel(DefaultTableModel):

    def __init__(self, data, columnNames):
        DefaultTableModel.__init__(self, data, columnNames)

    def isCellEditable(self, row, column):
        canEdit = [False, False, False]
        return canEdit[column]

    def getColumnClass(self, column):
        columnClasses = [Integer, String, String]
        return columnClasses[column]


class RegexTableMouseListener(MouseListener):

    def getClickedIndex(self, event):
        eventTable = event.getSource()
        row = eventTable.getSelectedRow()
        return eventTable.getValueAt(row, 0)

    def getClickedRow(self, event):
        eventTable = event.getSource()
        return eventTable.getModel().getDataVector().elementAt(eventTable.getSelectedRow())

    def mouseClicked(self, event):
        if event.getClickCount() == 1:
            print("Single-click: {}".format(self.getClickedRow(event)))

        if event.getClickCount() == 2:
            print("Double-click: {}".format(self.getClickedRow(event)))

    def mouseEntered(self, event):
        pass

    def mouseExited(self, event):
        pass

    def mousePressed(self, event):
        pass

    def mouseReleased(self, event):
        pass


class RegexTable(JTable):

    def __init__(self, data, columnNames):
        model = RegexTableModel(data, columnNames)
        self.setModel(model)
        self.setAutoCreateRowSorter(True)
        self.getTableHeader().setReorderingAllowed(False)
        self.addMouseListener(RegexTableMouseListener())


# support for burp-exceptions
try:
    FixBurpExceptions()
except:
    pass