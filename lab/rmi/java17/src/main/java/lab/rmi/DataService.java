package lab.rmi;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.util.List;

public interface DataService extends Remote {
    List<String> getUsers() throws RemoteException;
    String getUserData(String userId) throws RemoteException;
}
