

import java.util.*;
/**
 *
 * @author Usuario
 */
public class IntroACripto {

    public static <K, V extends Comparable<V> > Map<K, V>
    valueSort(final Map<K, V> map)
    {
        // Static Method with return type Map and
        // extending comparator class which compares values
        // associated with two keys
        Comparator<K> valueComparator = new Comparator<K>() {
            
                  // return comparison results of values of
                  // two keys
                  public int compare(K k1, K k2)
                  {
                      int comp = map.get(k1).compareTo(
                          map.get(k2));
                      if (comp == 0)
                          return 1;
                      else
                          return comp;
                  }
            
              };
        
        // SortedMap created using the comparator
        Map<K, V> sorted = new TreeMap<K, V>(valueComparator);
        
        sorted.putAll(map);
        
        return sorted;
    }

    /**
     * @param args the command line arguments
     * @throws java.lang.Exception
     */
    public static void main (String[] args) throws java.lang.Exception
   {
        Scanner input = new Scanner (System.in);
        String texto = input.nextLine().toLowerCase();
        TreeMap<String, Integer> map = new TreeMap<>();
        String alfabeto[] = {"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z"};

        ArrayList<String> vetor1 = new ArrayList<>();
        String vetor2[] = {"y", "w", "k", "j", "z", "x", "h", "f", "b", "v", "q", "g", "p", "l", "c", "u", "m", "t", "d", "n", "i", "r", "s", "o", "e", "a"};

        for(int i=0; i<alfabeto.length; i++)
            map.put(alfabeto[i], (contChars(texto, alfabeto[i])));
       

        Map sortedMap = valueSort(map);
        Set set = sortedMap.entrySet();
        // Get an iterator
        Iterator i = set.iterator();
        // Display elements
        while(i.hasNext()) {
            Map.Entry me = (Map.Entry)i.next();
            vetor1.add((String)me.getKey()); 
        }

        //System.out.println();
        for(int cont=0; cont<texto.length(); cont++){
            char oldChar = texto.charAt(cont);
            int index;
            for(index = 0; index<vetor1.size(); index++){
                if(vetor1.get(index).equals(String.valueOf(oldChar))){
                    break;
                }
            }
            texto = replace(texto, cont, vetor2[index].charAt(0));
        }
        
        
        System.out.println();

        System.out.println(texto);
        input.close();
   }

   private static String replace(String str, int index, char replace){     
    if(str==null){
        return str;
    }else if(index<0 || index>=str.length()){
        return str;
    }
    char[] chars = str.toCharArray();
    chars[index] = replace;
    return String.valueOf(chars);       
}
   
   
    private static int contChars(String someString, String someChar){
        int count=0;
        for (int i = 0; i < someString.length(); i++) {
            if (someString.charAt(i) == someChar.charAt(0)) {
                count++;
            }
        }
        return count;
    }

}