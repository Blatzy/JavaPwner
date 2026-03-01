package lab.rmi;

import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;

public class HelloServiceImpl extends UnicastRemoteObject implements HelloService {

    private static final long serialVersionUID = 1L;

    public HelloServiceImpl(int port) throws RemoteException {
        super(port);
    }

    @Override
    public String sayHello(String name) throws RemoteException {
        return "Hello, " + name + "! [Java " + System.getProperty("java.version") + "]";
    }

    @Override
    public String getServerVersion() throws RemoteException {
        return System.getProperty("java.version");
    }
}
