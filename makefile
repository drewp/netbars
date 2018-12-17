build_image:
	docker build --network=host -t bang6:5000/netbars_x86:latest .
	docker push bang6:5000/netbars_x86:latest

shell:
	docker run --rm -it --cap-add SYS_PTRACE --net=host bang6:5000/netbars_x86:latest  /bin/bash

local_run:
	docker run --rm -it  --net=host  bang6:5000/netbars_x86:latest
