package me.gv7.woodpecker.plugin;

import me.gv7.woodpecker.plugin.exploits.CasExploit;
import me.gv7.woodpecker.plugin.payloads.CasPayloadGenerate;
import me.gv7.woodpecker.plugin.pocs.CasPoc;

import java.util.ArrayList;
import java.util.List;

public class CasRCE implements IPlugin{

    public static IExtenderCallbacks callbacks;
    public static IPluginHelper pluginHelper;
    @Override
    public void PluginMain(IExtenderCallbacks callbacks) {
        CasRCE.callbacks = callbacks;
        CasRCE.pluginHelper = callbacks.getPluginHelper();

        callbacks.setPluginName("CAS execute RCE");
        callbacks.setVulName("CAS反序列化一条龙");
        callbacks.setPluginAutor("Frost Blue");
        callbacks.setPluginVersion("0.1.0");
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
