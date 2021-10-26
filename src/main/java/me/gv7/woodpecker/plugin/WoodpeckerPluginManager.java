package me.gv7.woodpecker.plugin;

import me.gv7.woodpecker.vuldb.execution.deserial.VulPluginImpl;

public class WoodpeckerPluginManager implements IPluginManager{
    @Override
    public void registerPluginManagerCallbacks(IPluginManagerCallbacks iPluginManagerCallbacks) {
        final VulPluginImpl casRCE = new VulPluginImpl();
        iPluginManagerCallbacks.registerVulPlugin(casRCE);
    }
}
