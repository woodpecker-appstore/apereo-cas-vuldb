package me.gv7.woodpecker.plugin;

import me.gv7.woodpecker.plugin.exploits.CasExploit;
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

        callbacks.setVulPluginName("CAS execute RCE");
        callbacks.setVulName("CAS反序列化一条龙");
        callbacks.setVulPluginAuthor("Frost Blue");
        callbacks.setVulPluginVersion("0.1.1");
        callbacks.setVulProduct("Apereo CAS");
        callbacks.setVulSeverity("high");
        callbacks.setVulId("woodpecker-2016-0408");

        final List<IPayloadGenerator> payloadGeneratorList = new ArrayList<IPayloadGenerator>();
        payloadGeneratorList.add(new CasPayloadGenerate());
        callbacks.registerPayloadGenerator(payloadGeneratorList);

        final List<IExploit> exploitsList = new ArrayList<>();
        exploitsList.add(new CasExploit());
        callbacks.registerExploit(exploitsList);

        callbacks.registerPoc(new CasPoc());
    }
}
