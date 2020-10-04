package me.gv7.woodpecker.plugin;

public class WoodpeckerPluginManager implements IPluginManager{
    @Override
    public void registerPluginManagerCallbacks(IPluginManagerCallbacks iPluginManagerCallbacks) {
        final CasRCE casRCE = new CasRCE();
        iPluginManagerCallbacks.registerPlugin(casRCE);
    }
}
