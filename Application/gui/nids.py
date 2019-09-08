import threading
import live_core
import copy
import gi


gi.require_version('Gtk', '3.0')
from gi.repository import Gtk

class TreeViewFilterWindow(Gtk.Window):
    def __init__(self):
        Gtk.Window.__init__(self, title="Network Intrusion Detection System")
        self.set_border_width(10)
        self.set_resizable(True)

        # Khoi tao grid
        self.grid = Gtk.Grid()
        self.grid.set_column_homogeneous(True)
        self.grid.set_row_homogeneous(True)
        self.add(self.grid)

        self.label = Gtk.Label()
        self.noteb = Gtk.Notebook()
        
        # Tao ListStore
        self.software_list_store = Gtk.ListStore(str, str, str, str, str, str, str)
        self.current_filter_language = None

        self.software_list_store_nginx = Gtk.ListStore(str, str, str, str, str, str, str, str, str)
        self.software_list_store_apache = Gtk.ListStore(str, str, str, str, str, str, str, str, str, str)

        self.current_filter_language_apache = None
        self.current_filter_language_nginx = None
        # Tao filter 
        self.language_filter = self.software_list_store.filter_new()
        self.language_filter_nginx = self.software_list_store_nginx.filter_new()
        self.language_filter_apache = self.software_list_store_apache.filter_new()
        # Gan su kien cho filter
        self.language_filter.set_visible_func(self.language_filter_func)
        self.language_filter_nginx.set_visible_func(self.language_filter_func_nginx)
        self.language_filter_apache.set_visible_func(self.language_filter_func_apache)
        # Tao treeview 
        self.tree_view = Gtk.TreeView.new_with_model(self.language_filter)
        for i, column_title in enumerate(["MAC Addr", "IP Addr",
                                          "User Agent", "Payload", "Label"]):
            renderer = Gtk.CellRendererText()
            column = Gtk.TreeViewColumn(column_title, renderer, text=i,
                                        foreground=5, background=6)
            column.set_resizable(True)
            column.set_expand(False)
            column.set_fixed_width(150)
            column.set_min_width(50)
            self.tree_view.append_column(column)

        self.tree_view_apache = Gtk.TreeView.new_with_model(self.language_filter_apache)
        for i, column_title in enumerate(["Date", "IP", "Method",
                                          "User Agent", "Payload", "Status Code", "Length", "Label"]):
            renderer = Gtk.CellRendererText()
            column = Gtk.TreeViewColumn(column_title, renderer, text=i,
                                        foreground=8, background=9)
            column.set_resizable(True)
            column.set_expand(False)
            column.set_fixed_width(150)
            column.set_min_width(50)
            self.tree_view_apache.append_column(column)
            

        self.tree_view_nginx = Gtk.TreeView.new_with_model(self.language_filter_nginx)
        for i, column_title in enumerate(["Date", "IP", "Method",
                                          "User Agent", "Payload", "Length", "Label"]):
            renderer = Gtk.CellRendererText()
            column = Gtk.TreeViewColumn(column_title, renderer, text=i,
                                        foreground=7, background=8)
            column.set_resizable(True)
            column.set_expand(False)
            column.set_fixed_width(150)
            column.set_min_width(50)
            self.tree_view_nginx.append_column(column)


        self.buttons = list()
        # Tao button
        self.start_button = Gtk.Button("Start")
        self.buttons.append(self.start_button)
        self.start_button.connect("clicked", self.start_run)
        open2_button = Gtk.Button("Open pcap")
        self.buttons.append(open2_button)
        open2_button.connect("clicked", self.open_pcap)
        open_button = Gtk.Button("Open Nginx log")
        self.buttons.append(open_button)
        open_button.connect("clicked", self.open_log)
        open1_button = Gtk.Button("Open Apache log")
        self.buttons.append(open1_button)
        open1_button.connect("clicked", self.open_alog)
        # Gan su kien cho button
        for classified_data in ["anomalous", "normal", "all"]:
            button = Gtk.Button(classified_data)
            self.buttons.append(button)
            button.connect("clicked", self.on_selection_button_clicked)

        # Dan layout
        self.scrollable_tree_list = Gtk.ScrolledWindow()
        self.scrollable_tree_list.set_vexpand(True)
        self.scrollable_tree_list1 = Gtk.ScrolledWindow()
        self.scrollable_tree_list1.set_vexpand(True)
        self.scrollable_tree_list2 = Gtk.ScrolledWindow()
        self.scrollable_tree_list2.set_vexpand(True)
        self.grid.attach(self.noteb, 0, 0, 8, 10)
        self.grid.attach_next_to(self.buttons[0], self.noteb,
                                 Gtk.PositionType.BOTTOM, 1, 1)
        for i, button in enumerate(self.buttons[1:]):
            self.grid.attach_next_to(button, self.buttons[i],
                                     Gtk.PositionType.RIGHT, 1, 1)
        self.grid.attach_next_to(self.label, self.buttons[6], Gtk.PositionType.RIGHT, 1, 1)
        self.label.set_text("Welcome")
        self.scrollable_tree_list.add(self.tree_view_nginx)
        self.scrollable_tree_list1.add(self.tree_view_apache)
        self.scrollable_tree_list2.add(self.tree_view)
        self.noteb.append_page(self.scrollable_tree_list2, Gtk.Label("Pcap"))
        self.noteb.append_page(self.scrollable_tree_list, Gtk.Label("Nginx"))
        self.noteb.append_page(self.scrollable_tree_list1, Gtk.Label("Apache"))
        self.show_all()
        self.builder = []

    def language_filter_func(self, model, iter, data):
        """Tests if the language in the row is the one in the filter"""
        if self.current_filter_language is None or self.current_filter_language == "all":
            return True
        else:
            return model[iter][4] == self.current_filter_language

    def language_filter_func_apache(self, model, iter, data):
        """Tests if the language in the row is the one in the filter"""
        if self.current_filter_language_apache is None or self.current_filter_language_apache == "all":
            return True
        else:
            return model[iter][7] == self.current_filter_language_apache

    def language_filter_func_nginx(self, model, iter, data):
        """Tests if the language in the row is the one in the filter"""
        if self.current_filter_language_nginx is None or self.current_filter_language_nginx == "all":
            return True
        else:
            return model[iter][6] == self.current_filter_language_nginx

    def on_selection_button_clicked(self, widget):
        """Called on any of the button clicks"""
        # Gan nhan ung voi cac nut filter
        self.current_filter_language = widget.get_label()
        self.current_filter_language_apache = widget.get_label()
        self.current_filter_language_nginx = widget.get_label()
        print("%s language selected!" % self.current_filter_language_apache)
        # Cap nhat treeview khi chon filter
        self.language_filter.refilter()
        self.language_filter_apache.refilter()
        self.language_filter_nginx.refilter()
    def open_log(self, widget):
        dialog = Gtk.FileChooserDialog("Please choose a file", self,
                                       Gtk.FileChooserAction.OPEN,
                                       (Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
                                        Gtk.STOCK_OPEN, Gtk.ResponseType.OK))

        response = dialog.run()
        if response == Gtk.ResponseType.OK:
            print("Open clicked")
            print("File selected: " + dialog.get_filename())
            global addl
            global STOP_EV
            global lognum
            STOP_EV.clear()
            self.software_list_store_nginx.clear()
            self.noteb.set_current_page(1)
            worker1 = threading.Thread(target=live_core.start_nginx, args=[addl, lognum, STOP_EV, dialog.get_filename()])
            worker1.start()
        elif response == Gtk.ResponseType.CANCEL:
            print("Cancel clicked")
        dialog.destroy()

    
    def open_alog(self, widget):
        dialog = Gtk.FileChooserDialog("Please choose a file", self,
                                       Gtk.FileChooserAction.OPEN,
                                       (Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
                                        Gtk.STOCK_OPEN, Gtk.ResponseType.OK))

        response = dialog.run()
        if response == Gtk.ResponseType.OK:
            print("Open clicked")
            print("File selected: " + dialog.get_filename())
            global addl
            global STOP_EV
            global lognum
            STOP_EV.clear()
            self.software_list_store_apache.clear()
            self.noteb.set_current_page(2)
            worker2 = threading.Thread(target=live_core.start_apache, args=[addl, lognum, STOP_EV, dialog.get_filename()])
            worker2.start()
        elif response == Gtk.ResponseType.CANCEL:
            print("Cancel clicked")
        dialog.destroy()

    def open_pcap(self, widget):
        dialog = Gtk.FileChooserDialog("Please choose a file", self,
                                       Gtk.FileChooserAction.OPEN,
                                       (Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
                                        Gtk.STOCK_OPEN, Gtk.ResponseType.OK))

        response = dialog.run()
        if response == Gtk.ResponseType.OK:
            print("Open clicked")
            print("File selected: " + dialog.get_filename())
            global addl
            global STOP_EV
            global lognum
            STOP_EV.clear()
            self.software_list_store.clear()
            self.noteb.set_current_page(0)
            worker3 = threading.Thread(target=live_core.start_pcap, args=[addl, lognum, STOP_EV, dialog.get_filename()])
            worker3.start()
        elif response == Gtk.ResponseType.CANCEL:
            print("Cancel clicked")
        dialog.destroy()
    

    def add_line(self, line):
        if line != "end cap": 
            self.builder.append(line)
        else:
            if len(self.builder)==8:
                blah = copy.deepcopy(self.builder)
                if blah[7] == 'normal':
                    blah.append('black')
                    blah.append('white')
                else:
                    blah.append('white')
                    blah.append('red')
                self.software_list_store_apache.insert(0, blah)
                self.builder = []
            if len(self.builder)==7:
                blah = copy.deepcopy(self.builder)
                if blah[6] == 'normal':
                    blah.append('black')
                    blah.append('white')
                else:
                    blah.append('white')
                    blah.append('red')
                self.software_list_store_nginx.insert(0, blah)
                self.builder = []
            if len(self.builder)==5:
                blah = copy.deepcopy(self.builder)
                if blah[4] == 'normal':
                    blah.append('black')
                    blah.append('white')
                else:
                    blah.append('white')
                    blah.append('red')
                self.software_list_store.insert(0, blah)
                self.builder = []

    def count_line(self, num):
             ll = num
             bleh = "Analyzing " + ll + " requests"
             self.label.set_text(bleh)
 
    def start_run(self, widget):
        global addl
        global STOP_EV
        global lognum
        global addsniff
        #self.software_list_store_apache.clear()
        #self.software_list_store_nginx.clear()
        worker = threading.Thread(target=live_core.start_sniff, args=[addl, addsniff, lognum, STOP_EV])
        worker.start()
        self.start_button.set_label("Stop")
        self.start_button.connect("clicked", self.stop_run)
        STOP_EV.clear()

    def stop_run(self, widget):
        global STOP_EV
        self.start_button.set_label("Start")
        self.start_button.connect("clicked", self.start_run)
        STOP_EV.set()


win = TreeViewFilterWindow()
win.connect("delete-event", Gtk.main_quit)
win.show_all()

STOP_EV = threading.Event()


def addl(line):
    global win
    win.add_line(line)
def addsniff(line):
    global win
    win.add_line(line)
def lognum(num):
    global win
    win.count_line(num)

Gtk.main()
