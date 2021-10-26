package me.gv7.woodpecker.vuldb.execution.deserial;

import me.gv7.woodpecker.plugin.*;

import java.util.ArrayList;
import java.util.List;

public class VulPluginImpl implements IVulPlugin {

    public static IVulPluginCallbacks callbacks;
    public static IPluginHelper pluginHelper;
    public static IDNSLog idnsLog;
    public static IHttpLog iHttpLog;

    @Override
    public void VulPluginMain(IVulPluginCallbacks vulPluginCallbacks) {
        callbacks = vulPluginCallbacks;
        pluginHelper = callbacks.getPluginHelper();
        idnsLog = callbacks.getDNSLogManager();
        iHttpLog = callbacks.getHttpLogManager();

        callbacks.setVulPluginName("Apereo cas execution deserial exploit");
        callbacks.setVulName("Apereo cas execution deserial");
        callbacks.setVulPluginAuthor("ppsoft1991 c0ny1");
        callbacks.setVulPluginVersion("0.3.0");
        callbacks.setVulProduct("Apereo cas");
        callbacks.setVulSeverity(IVulPluginCallbacks.VUL_CATEGORY_RCE);
        callbacks.setVulId("");

        final List<IPayloadGenerator> payloadGeneratorList = new ArrayList<IPayloadGenerator>();
        payloadGeneratorList.add(new EncrpytPayloadGenerate());
        payloadGeneratorList.add(new DecryptPayloadGenerator());
        callbacks.registerPayloadGenerator(payloadGeneratorList);

        final List<IExploit> exploitsList = new ArrayList<>();
        exploitsList.add(new EchoExecuteCommandExploit());
        exploitsList.add(new CustomSerialDataExploit());
        callbacks.registerExploit(exploitsList);

        callbacks.registerPoc(new PocImpl());
    }
}
