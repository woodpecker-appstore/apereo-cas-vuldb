package me.gv7.woodpecker.plugin;

import me.gv7.woodpecker.plugin.exploits.CasExploit;
import me.gv7.woodpecker.plugin.payloads.CasPayloadDecoder;
import me.gv7.woodpecker.plugin.payloads.CasPayloadGenerate;
import me.gv7.woodpecker.plugin.pocs.CasPoc;

import java.util.ArrayList;
import java.util.List;

public class CasRCE implements IVulPlugin{

    public static IVulPluginCallbacks callbacks;
    public static IPluginHelper pluginHelper;

    @Override
    public void VulPluginMain(IVulPluginCallbacks vulPluginCallbacks) {
        callbacks = vulPluginCallbacks;
        pluginHelper = callbacks.getPluginHelper();

        callbacks.setVulPluginName("Apereo cas execution deserial exploit");
        callbacks.setVulName("Apereo cas execution deserial");
        callbacks.setVulPluginAuthor("ppsoft1991&c0ny1");
        callbacks.setVulPluginVersion("0.2.0");
        callbacks.setVulProduct("Apereo cas");
        callbacks.setVulSeverity(IVulPluginCallbacks.VUL_CATEGORY_RCE);
        callbacks.setVulId("woodpecker-2016-0408");

        final List<IPayloadGenerator> payloadGeneratorList = new ArrayList<IPayloadGenerator>();
        payloadGeneratorList.add(new CasPayloadGenerate());
        payloadGeneratorList.add(new CasPayloadDecoder());
        callbacks.registerPayloadGenerator(payloadGeneratorList);

        final List<IExploit> exploitsList = new ArrayList<>();
        exploitsList.add(new CasExploit());
        callbacks.registerExploit(exploitsList);

        callbacks.registerPoc(new CasPoc());
    }
}
