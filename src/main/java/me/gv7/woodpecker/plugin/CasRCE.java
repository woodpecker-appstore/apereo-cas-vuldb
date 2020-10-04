package me.gv7.woodpecker.plugin;

import me.gv7.woodpecker.plugin.payloads.CasPayloadGenerate;

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
        callbacks.setVulName("反序列化生成器");
        callbacks.setPluginAutor("Frost Blue");
        callbacks.setPluginVersion("0.1.0");
        callbacks.setVulProduct("Apereo CAS");
        callbacks.setVulSeverity("high");
        callbacks.setVulId("woodpecker-2016-0408");

        final List<IPayloadGenerator> payloadGeneratorList = new ArrayList<IPayloadGenerator>();
        payloadGeneratorList.add(new CasPayloadGenerate());
        callbacks.registerPayloadGenerator(payloadGeneratorList);
    }
}
