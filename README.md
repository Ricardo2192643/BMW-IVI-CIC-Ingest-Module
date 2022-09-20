# Autopsy BMW-IVI-CIC-Ingest-Module 
## Analysis of in-vehicle infotainment systems of BMW brand vehicles, in the 2010 and 2012 series 3 models, with IVI CIC systems

As the Autopsy tool does not recognize the QNX file system, we have to mount the partitions and then manually load the partitions/folders to the autopsy tool and then do analysis with this ingest module.

Mount the Partitions

To mount the partitions we use Kali linux

 - We run the following commands:

sudo fdisk -lu simao.001
![image](https://user-images.githubusercontent.com/33206506/190868473-71915f6d-47f4-4dc7-8b5b-ed00a7222fc1.png)

sudo losetup --partscan --find --show simao.001

ls -la /dev/loop0*

![image](https://user-images.githubusercontent.com/33206506/190868500-f224a0be-ebd0-4f17-8070-0af34065ef40.png)
![image](https://user-images.githubusercontent.com/33206506/190868506-6da54711-bcb4-4726-a9bd-a29524add5db.png)

sudo mount -r -t qnx6 /dev/loop0p5 /home/kali/Desktop/bmwsimao/particao5/

sudo mount -r -t qnx6 /dev/loop0p6 /home/kali/Desktop/bmwsimao/particao6/

sudo mount -r -t qnx6 /dev/loop0p7 /home/kali/Desktop/bmwsimao/particao7/

sudo mount -r -t qnx6 /dev/loop0p8 /home/kali/Desktop/bmwsimao/particao8/

sudo mount -r -t qnx6 /dev/loop0p9 /home/kali/Desktop/bmwsimao/particao9/

sudo mount -r -t qnx6 /dev/loop0p10 /home/kali/Desktop/bmwsimao/particao10/

sudo mount -r -t qnx6 /dev/loop0p1 /home/kali/Desktop/bmwsimao/particao1/

![image](https://user-images.githubusercontent.com/33206506/190868527-3492bda0-7a7e-4960-924d-97e43f2287a1.png)

After all available partitions are mounted, one folder per partition is created, in this case I named each partition.

![image](https://user-images.githubusercontent.com/33206506/190868543-34ec45ae-1ec3-42d1-b853-a5a0c52ddd6e.png)

Autopsy

To load the partitions to the Autopsy tool, we first have to select what type of data we are going to select, in this case we choose Logical Files, to add the folders that correspond to each partition.

![image](https://user-images.githubusercontent.com/33206506/190868642-2adc99d3-b3fd-4f1a-b910-8baeb4ba4afc.png)

![image](https://user-images.githubusercontent.com/33206506/190868669-075447fc-da0c-423b-9dce-043370e33460.png)

![image](https://user-images.githubusercontent.com/33206506/190868685-fb721ae2-086c-46c6-98e9-690f73ddef8b.png)

![image](https://user-images.githubusercontent.com/33206506/190868724-4b47c5e1-8b66-4a2e-95d1-1c78f84a8a54.png)

![image](https://user-images.githubusercontent.com/33206506/190868753-7a4fc258-f44f-40cc-88aa-e9c493fcff0a.png)

![image](https://user-images.githubusercontent.com/33206506/190868762-55ff54a7-0ddc-43f9-a97c-ecbe9996e3bf.png)









