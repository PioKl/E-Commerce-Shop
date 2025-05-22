"use client";

import { Button } from "@/components/ui/button";
import { useRouter } from "next/navigation";
import { Plus } from "lucide-react";
import { CartItem } from "@/types";
import { toast } from "sonner";
import { addItemToCart } from "@/lib/actions/cart.actions";

const AddToCart = ({ item }: { item: CartItem }) => {
  const router = useRouter();

  const handleAddToCart = async () => {
    const res = await addItemToCart(item);

    if (!res.success) {
      toast.error(res.message);

      return;
    }

    //Handle success add to cart
    toast.success(`${item.name} added to cart`, {
      action: (
        <Button
          className="bg-primary text-white hover:bg-gray-800"
          onClick={() => router.push("/cart")}
        >
          Go to cart
        </Button>
      ),
    });
  };
  return (
    <Button className="w-full" type="button" onClick={handleAddToCart}>
      <Plus />
      Add to cart
    </Button>
  );
};

export default AddToCart;
