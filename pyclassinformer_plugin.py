import ida_idaapi
import ida_kernwin

import os
import sys

dirpath = os.path.dirname(os.path.abspath(__file__))
script_dir = os.path.join(dirpath, "pyclassinformer")
if script_dir not in sys.path:
    sys.path.append(script_dir)

ida_idaapi.require("qtutils")
import qtutils

class pci_plugin_t(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP
    comment = "Yet Another RTTI Parser"
    wanted_name = "PyClassInformer"
    wanted_hotkey = "Alt-Shift-L"
    help = "Press '" + wanted_hotkey + "' to display the " + wanted_name + " result."
    
    toolbar_displayed_name = wanted_name
    toolbar_name = toolbar_displayed_name + 'Toolbar'
    
    action_name = "pyclassinformer:execute"
    menu_path = "Edit/Plugins/"
    
    icon_data = open(os.path.join(script_dir, "pci_icon.png"), "rb").read()
    act_icon = ida_kernwin.load_custom_icon(data=icon_data, format="png")
    
    class exec_from_toolbar(ida_kernwin.action_handler_t):
        action_name = "pyclassinformer:execute_toolbar"
        def __init__(self, plugin):
            ida_kernwin.action_handler_t.__init__(self)
            import weakref
            self.v = weakref.ref(plugin)
        
        def activate(self, ctx):
            run_pci(self.v().act_icon)
            
        def update(self, ctx):
            return ida_kernwin.AST_ENABLE_ALWAYS
        
    def attach_to_toolbar(self):
        # attach to menu
        ida_kernwin.attach_action_to_menu(
            self.menu_path,
            self.action_name,
            ida_kernwin.SETMENU_APP)

        # attach to toolbar
        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
            pci_plugin_t.exec_from_toolbar.action_name,
            pci_plugin_t.comment,
            pci_plugin_t.exec_from_toolbar(self),
            None,
            self.wanted_name,
            self.act_icon))
        
        # Insert the action in a toolbar
        ida_kernwin.create_toolbar(self.toolbar_name, self.toolbar_displayed_name)
        ida_kernwin.attach_action_to_toolbar(self.toolbar_name, pci_plugin_t.exec_from_toolbar.action_name)
        
        # install ui hook to enable toolbar later
        self.ph = qtutils.enable_toolbar_t(self.toolbar_name)
        
    def init(self):
        ida_kernwin.msg("############### %s (%s) ###############%s" % (self.wanted_name, self.comment, os.linesep))
        ida_kernwin.msg("%s%s" % (self.help, os.linesep))

        # attach to menu
        self.attach_to_toolbar()

        return self.flags

    def run(self, arg):
        run_pci(icon=self.act_icon)
        
    def term(self):
        ida_kernwin.detach_action_from_menu(self.menu_path, self.action_name)


def run_pci(icon=-1):
    ida_idaapi.require("pyclassinformer")
    import pyclassinformer
    pyclassinformer.run_pci(icon)


class RegisterIcon(ida_kernwin.UI_Hooks):
    def updated_actions(self):
        if ida_kernwin.update_action_icon(pci_plugin_t.menu_path + pci_plugin_t.wanted_name, pci_plugin_t.act_icon):
            # unhook this if it's successful
            self.unhook()


def PLUGIN_ENTRY():
    ri = RegisterIcon()
    ri.hook()
    return pci_plugin_t()


